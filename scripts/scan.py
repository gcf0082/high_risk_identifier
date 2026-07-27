#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
high_risk_identifier 扫描器

按 rules.yaml 定义的规则扫描目标目录:
  - content 组:逐行匹配文件内容,输出 文件路径 + 行号 + 行内容
  - path 组   :匹配文件相对路径,输出只有文件路径(不含内容)
用法:
  python3 scan.py <目标目录> [-o 输出.json] [-r rules.yaml] [--min-severity high|medium|low] [-w N]
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

CONFIG = None  # 各进程共享的编译后规则(fork 继承)


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
            groups.append({
                'exts': {e.lower() for e in m['ext']} if m.get('ext') else None,
                'paths': m.get('paths'),
                'content': [re.compile(p, flags) for p in m.get('content', [])],
                'path': [re.compile(p, flags) for p in m.get('path', [])],
            })
        compiled_rules.append({
            'id': rule['id'],
            'name': rule.get('name', ''),
            'severity': sev,
            'groups': groups,
        })
    return {
        'version': cfg.get('version'),
        'min_severity': min_sev,
        'exclude': cfg.get('exclude_paths', []),
        'rules': compiled_rules,
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


def scan_file(job):
    """扫描单个文件,返回 finding 列表"""
    root, rel = job
    findings = []

    # --- path 组:只匹配相对路径,输出不含内容 ---
    path_hits = {}      # rule_id -> {'rule': rule, 'patterns': set()}
    content_groups = []  # [(rule, group)]
    for rule in CONFIG['rules']:
        for g in rule['groups']:
            if not group_applies(rel, g):
                continue
            for p in g['path']:
                if p.search(rel):
                    hit = path_hits.setdefault(rule['id'], {'rule': rule, 'patterns': set()})
                    hit['patterns'].add(p.pattern)
            if g['content']:
                content_groups.append((rule, g))

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

        acc = {}   # rule_id -> {'rule': rule, 'matches': {(pattern, lineno): text}}
        for lineno, line in enumerate(lines, line_offset):
            for rule, g in content_groups:
                for p in g['content']:
                    m = p.search(line)
                    if m:
                        entry = acc.setdefault(rule['id'], {'rule': rule, 'matches': {}})
                        entry['matches'].setdefault((p.pattern, lineno), line.strip()[:LINE_PREVIEW])

        for rid, info in acc.items():
            r = info['rule']
            matches = [
                {'line': lineno, 'pattern': pat, 'text': txt}
                for (pat, lineno), txt in sorted(info['matches'].items(), key=lambda x: x[0][1])
            ][:MAX_MATCHES_PER_FINDING]
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
    ap.add_argument('target', help='被扫描的目标目录')
    ap.add_argument('-o', '--output', default=None,
                    help='结果 JSON 输出路径(默认 <目标目录>/.risk_out/scan_result.json)')
    ap.add_argument('-r', '--rules', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rules.yaml'),
                    help='规则文件路径(默认脚本同目录 rules.yaml)')
    ap.add_argument('--min-severity', default=None, help='覆盖规则文件的 min_severity(high/medium/low)')
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

    # 收集文件列表
    files, n_excluded = [], 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            rel = os.path.relpath(os.path.join(dirpath, fn), root).replace(os.sep, '/')
            if excluded(rel):
                n_excluded += 1
                continue
            files.append(rel)

    jobs = [(root, rel) for rel in files]
    workers = max(1, min(args.workers, len(files) or 1))

    findings = []
    if workers == 1 or len(jobs) < 2:
        findings = scan_batch(jobs)
    else:
        chunks = [jobs[i::workers] for i in range(workers)]   # 轮询分片,负载均衡
        with Pool(workers) as pool:                            # fork 模式继承 CONFIG
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
    for sev in ('high', 'medium', 'low'):
        if sev in summary:
            print(f'  {sev}: {summary[sev]}')


if __name__ == '__main__':
    main()
