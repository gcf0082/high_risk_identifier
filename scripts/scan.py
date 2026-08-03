#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
high_risk_identifier 扫描器

按 rules.yaml 定义的规则扫描目标目录:
  - content 组:逐行匹配文件内容,输出 文件路径 + 行号 + 列号 + 行内容(可选前后上下文)
  - path 组   :匹配文件相对路径,输出只有文件路径(不含内容)
用法:
  python3 scan.py [目标目录] [-o 输出.json] [-r rules.yaml] [--min-severity high|medium|low]
                  [-e py,java] [-p "**/src/**"] [-x "**/test/**"] [-C N] [-w N]
  不带参数时扫描当前目录,使用脚本同目录的默认规则,结果写入 ./.risk_out/scan_result.json
"""
import argparse
import fnmatch
import json
import os
import re
import sys
from multiprocessing import Pool, cpu_count

import yaml

MAX_FILE_SIZE = 10 * 1024 * 1024      # 超过则跳过内容扫描
MAX_MATCHES_PER_FINDING = 50          # 单条 finding 最多记录的命中行数
LINE_PREVIEW = 200                    # 命中行内容截断长度
BINARY_SNIFF = 8192                   # 前 N 字节含 NUL 视为二进制

CONFIG = None  # 各进程共享的编译后规则


def compile_rules(rules_path, min_severity_override=None):
    with open(rules_path, encoding='utf-8') as f:
        cfg = yaml.safe_load(f)
    levels = cfg.get('severity_levels', ['high', 'medium', 'low'])
    min_sev = min_severity_override or cfg.get('min_severity', 'high')
    if min_sev not in levels:
        raise ValueError(f'未知级别: {min_sev},可选 {levels}')
    min_idx = levels.index(min_sev)
    global_cs = cfg.get('case_sensitive', True)

    compiled_rules = []
    for rule in cfg.get('rules', []):
        sev = rule.get('severity', 'low')
        if sev not in levels:
            raise ValueError(f"规则 {rule.get('id')} 的 severity 非法: {sev}")
        if levels.index(sev) > min_idx:      # 低于 min_severity 的规则不启用
            continue
        flags = 0 if rule.get('case_sensitive', global_cs) else re.IGNORECASE
        groups = []
        for m in rule.get('match', []):
            content_pats = m.get('content', [])
            groups.append({
                'exts': {e.lower() for e in m['ext']} if m.get('ext') else None,
                'paths': m.get('paths'),
                'content': [re.compile(p, flags) for p in content_pats],
                # 合并正则:逐行扫描时先做一次 search 预筛,命中后才逐条跑单正则
                'content_re': (re.compile('|'.join(f'(?:{p})' for p in content_pats), flags)
                               if content_pats else None),
                'path': [re.compile(p, flags) for p in m.get('path', [])],
            })
        compiled_rules.append({
            'id': rule['id'],
            'name': rule.get('name', ''),
            'severity': sev,
            'groups': groups,
        })

    # 按后缀索引 content 组:扫描时按文件后缀直接取候选组,避免每个文件遍历全部规则
    content_by_ext = {}
    content_any = []      # 不限后缀的 content 组,对所有文件生效
    for rule in compiled_rules:
        for g in rule['groups']:
            if not g['content']:
                continue
            if g['exts'] is None:
                content_any.append((rule, g))
            else:
                for e in g['exts']:
                    content_by_ext.setdefault(e, []).append((rule, g))

    return {
        'version': cfg.get('version'),
        'min_severity': min_sev,
        'exclude': cfg.get('exclude_paths', []),
        'rules': compiled_rules,
        'content_by_ext': content_by_ext,
        'content_any': content_any,
        'context_lines': 0,     # 由 main 按 -C 参数覆盖
    }


def ext_of(rel):
    base = rel.rsplit('/', 1)[-1]
    return base.rsplit('.', 1)[-1].lower() if '.' in base else ''


def group_applies(rel, g):
    """ext 过滤 AND paths glob 过滤"""
    if g['exts'] is not None and ext_of(rel) not in g['exts']:
        return False
    if g['paths'] and not any(fnmatch.fnmatch(rel, p) for p in g['paths']):
        return False
    return True


def excluded(rel):
    # 兼容根级目录:'node_modules/x' 也要能命中 '**/node_modules/**'
    return any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch('/' + rel, pat)
               for pat in CONFIG['exclude'])


def build_rule_exts():
    """从已编译规则中提取所有 exts(用于与 -e 指定的后缀取交集)"""
    all_exts = set()
    for rule in CONFIG['rules']:
        for g in rule['groups']:
            if g['exts'] is not None:
                all_exts.update(g['exts'])
    return all_exts


def file_in_filter(rel, user_exts, user_paths):
    """判断文件相对路径是否在用户指定的 ext+path 过滤范围内"""
    ext = ext_of(rel)
    # ext 过滤: 用户指定了 exts 时，必须命中用户指定的 exts
    if user_exts is not None:
        if ext not in user_exts:
            return False
    # path 过滤: 用户指定了 paths 时，必须命中用户指定的 paths
    if user_paths:
        if not any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch('/' + rel, p) for p in user_paths):
            return False
    return True


def fmt_size(path):
    """获取文件的人类可读大小"""
    try:
        b = os.path.getsize(path)
        if b >= 1024**3:
            return f'{b / 1024**3:.1f}G'
        if b >= 1024**2:
            return f'{b / 1024**2:.1f}M'
        if b >= 1024:
            return f'{b / 1024:.1f}K'
        return f'{b}B'
    except OSError:
        return 'unknown'


def init_worker(config):
    """Pool initializer: 在每个 worker 进程中设置 CONFIG (spawn 模式继承)"""
    global CONFIG
    CONFIG = config


def scan_file(job):
    """扫描单个文件,返回 finding 列表"""
    root, rel = job
    findings = []

    # --- path 组:只匹配相对路径,输出不含内容 ---
    path_hits = {}      # rule_id -> {'rule': rule, 'patterns': set()}
    for rule in CONFIG['rules']:
        for g in rule['groups']:
            if not g['path'] or not group_applies(rel, g):
                continue
            for p in g['path']:
                if p.search(rel):
                    hit = path_hits.setdefault(rule['id'], {'rule': rule, 'patterns': set()})
                    hit['patterns'].add(p.pattern)

    for rid, info in path_hits.items():
        r = info['rule']
        findings.append({
            'rule_id': rid,
            'rule_name': r['name'],
            'severity': r['severity'],
            'match_type': 'path',
            'file': rel,
            'matches': [{'pattern': p} for p in sorted(info['patterns'])],
        })

    # --- content 组:按后缀取候选组,再按 paths 过滤 ---
    ext = ext_of(rel)
    content_groups = [
        (rule, g)
        for rule, g in (CONFIG['content_by_ext'].get(ext, []) + CONFIG['content_any'])
        if not g['paths'] or any(fnmatch.fnmatch(rel, p) for p in g['paths'])
    ]

    # --- content 组:逐行匹配内容 ---
    if content_groups:
        full = os.path.join(root, rel)
        try:
            if os.path.getsize(full) > MAX_FILE_SIZE:
                return findings
            with open(full, 'rb') as f:
                data = f.read()
        except OSError:
            return findings
        if b'\x00' in data[:BINARY_SNIFF]:   # 二进制文件不做内容扫描
            return findings
        text = data.decode('utf-8', errors='replace')
        lines = text.splitlines()
        line_offset = 1
        if lines and lines[0].startswith('#!'):   # shebang 行不算命令执行
            lines = lines[1:]
            line_offset = 2

        acc = {}   # rule_id -> {'rule': rule, 'matches': {(pattern, lineno): (text, column)}}
        for lineno, line in enumerate(lines, line_offset):
            for rule, g in content_groups:
                if not g['content_re'].search(line):    # 合并正则预筛
                    continue
                for p in g['content']:
                    m = p.search(line)
                    if m:
                        entry = acc.setdefault(rule['id'], {'rule': rule, 'matches': {}})
                        entry['matches'].setdefault((p.pattern, lineno),
                                                    (line.strip()[:LINE_PREVIEW], m.start() + 1))

        ctx_n = CONFIG.get('context_lines', 0)
        for rid, info in acc.items():
            r = info['rule']
            matches = []
            ordered = sorted(info['matches'].items(), key=lambda x: x[0][1])[:MAX_MATCHES_PER_FINDING]
            for (pat, lineno), (txt, col) in ordered:
                hit = {'line': lineno, 'column': col, 'pattern': pat, 'text': txt}
                if ctx_n > 0:
                    lo = max(line_offset, lineno - ctx_n)
                    hi = min(line_offset + len(lines) - 1, lineno + ctx_n)
                    hit['context'] = [
                        {'line': i, 'text': lines[i - line_offset].strip()[:LINE_PREVIEW]}
                        for i in range(lo, hi + 1)
                    ]
                matches.append(hit)
            findings.append({
                'rule_id': rid,
                'rule_name': r['name'],
                'severity': r['severity'],
                'match_type': 'content',
                'file': rel,
                'matches': matches,
            })

    return findings


def scan_batch(jobs):
    out = []
    for j in jobs:
        out.extend(scan_file(j))
    return out


def main():
    ap = argparse.ArgumentParser(description='按 rules.yaml 扫描目标目录的高风险操作')
    ap.add_argument('target', nargs='?', default='.', help='被扫描的目标目录(默认当前目录)')
    ap.add_argument('-o', '--output', default=None,
                    help='结果 JSON 输出路径(默认 <目标目录>/.risk_out/scan_result.json)')
    ap.add_argument('-r', '--rules', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rules.yaml'),
                    help='规则文件路径(默认脚本同目录 rules.yaml)')
    ap.add_argument('--min-severity', default=None,
                    help='覆盖规则文件的 min_severity(high/medium/low);'
                         '当前 rules.yaml v4.0 仅含 high 规则,设为 medium/low 不会启用更多规则')
    ap.add_argument('-e', '--ext', default=None,
                    help='只扫描指定后缀的文件(逗号分隔,如 py,java,js),与规则取交集')
    ap.add_argument('-p', '--path', default=None,
                    help='只扫描路径匹配指定 glob 的文件(逗号分隔,如 **/src/**,**/core/**)')
    ap.add_argument('-x', '--exclude', default=None,
                    help='排除指定路径(glob,逗号分隔),可与规则中的 exclude_paths 叠加')
    ap.add_argument('-C', '--context', type=int, default=0,
                    help='每条命中附带前后 N 行上下文(默认 0,不附带)')
    ap.add_argument('-w', '--workers', type=int, default=cpu_count(), help='并行进程数(默认 CPU 核数)')
    args = ap.parse_args()

    root = os.path.abspath(args.target)
    if not os.path.isdir(root):
        print(f'错误: 目标目录不存在 {root}', file=sys.stderr)
        sys.exit(1)
    if args.output is None:
        args.output = os.path.join(root, '.risk_out', 'scan_result.json')

    global CONFIG
    CONFIG = compile_rules(args.rules, args.min_severity)
    CONFIG['context_lines'] = max(0, args.context)

    # 从规则中提取所有 exts,用于与 -e 指定的后缀取交集
    rule_exts = build_rule_exts()

    # 解析用户指定的 ext 过滤,与规则后缀取交集
    user_exts = None
    if args.ext:
        user_spec = {e.strip().lstrip('.').lower() for e in args.ext.split(',') if e.strip()}
        if rule_exts:
            dropped = user_spec - rule_exts
            if dropped:
                print(f'警告: -e 指定的后缀不在规则范围内,已丢弃: {",".join(sorted(dropped))}',
                      file=sys.stderr)
            user_exts = user_spec & rule_exts   # 交集:只保留规则中有的后缀
            if not user_exts:
                print(f'警告: -e 与规则后缀交集为空(指定: {",".join(sorted(user_spec))}),'
                      f'本次将扫不到任何文件', file=sys.stderr)
        else:
            user_exts = user_spec
    # 解析用户指定的 path 过滤(规则中的 paths 是规则匹配条件,不参与文件过滤,直接使用用户值)
    user_paths = None
    if args.path:
        user_paths = [p.strip() for p in args.path.split(',') if p.strip()]
    # 解析命令行排除路径（与规则 exclude_paths 合并）
    user_exclude = []
    if args.exclude:
        user_exclude = [p.strip() for p in args.exclude.split(',') if p.strip()]
    all_exclude = CONFIG['exclude'] + user_exclude

    # 收集文件列表
    files, n_excluded = [], 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            rel = os.path.relpath(os.path.join(dirpath, fn), root).replace(os.sep, '/')
            # 同时应用规则排除和命令行排除
            if any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch('/' + rel, p) for p in all_exclude):
                n_excluded += 1
                continue
            if not file_in_filter(rel, user_exts, user_paths):
                continue
            files.append(rel)

    if not files:
        print('警告: 过滤后文件数为 0,本次扫描不会有任何命中', file=sys.stderr)
        if args.path:
            print(f'警告: -p 指定的 glob 未匹配到任何文件: {args.path}', file=sys.stderr)

    jobs = [(root, rel) for rel in files]
    workers = max(1, min(args.workers, len(files) or 1))

    findings = []
    if workers == 1 or len(jobs) < 2:
        findings = scan_batch(jobs)
    else:
        chunks = [jobs[i::workers] for i in range(workers)]   # 轮询分片,负载均衡
        with Pool(workers, initializer=init_worker, initargs=(CONFIG,)) as pool:
            for res in pool.map(scan_batch, chunks):
                findings.extend(res)

    # 排序:级别 -> 规则 -> 文件
    sev_order = {'high': 0, 'medium': 1, 'low': 2}
    findings.sort(key=lambda x: (sev_order.get(x['severity'], 9), x['rule_id'], x['file']))

    summary = {}
    for f_ in findings:
        summary[f_['severity']] = summary.get(f_['severity'], 0) + 1

    report = {
        'target': root,
        'rules_version': CONFIG['version'],
        'min_severity': CONFIG['min_severity'],
        'scanned_files': len(files),
        'excluded_files': n_excluded,
        'summary': summary,
        'findings': findings,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f'扫描完成: {len(files)} 个文件(排除 {n_excluded}),命中 {len(findings)} 条 -> {args.output}')
    print(f'输出文件: {fmt_size(args.output)}')
    for sev in ('high', 'medium', 'low'):
        if sev in summary:
            print(f'  {sev}: {summary[sev]}')


if __name__ == '__main__':
    main()
