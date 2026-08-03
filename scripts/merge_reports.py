#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
merge_reports.py — 合并基线/补充两轮扫描结果,生成 risk-report.json 骨架

按 SKILL.md 第 4 步定义的结构输出:
  - 两轮 findings 合并,每条追加 verdict: {status: "pending"}
  - 去重:同文件同行且规则族相同(按 rule_id 前两段如 HR-COMMAND 归族)合并为一条,
    source 记 "base+custom",matches 合并去重(按 行号+pattern)
  - 排序:severity -> 规则 -> 文件(verdict 回填后由 annotate.py 重排)

用法:
  python merge_reports.py [目标目录] [-b scan-base.json] [-c scan-custom.json]
                          [-o risk-report.json] [-n "补充规则依据一句话"]
  不带参数时默认读写 <目标目录>/.risk_out/ 下的约定文件;scan-custom.json 不存在则只合基线。
"""
import argparse
import json
import os
import sys

SEV_ORDER = {'high': 0, 'medium': 1, 'low': 2}


def family_of(rule_id):
    """规则族:rule_id 前两段,如 HR-COMMAND-EXEC -> HR-COMMAND"""
    parts = rule_id.split('-', 2)
    return '-'.join(parts[:2]) if len(parts) >= 2 else rule_id


def match_lines(finding):
    """finding 的命中行号集合(path 型 finding 没有行号,返回空集)"""
    return {m['line'] for m in finding.get('matches', []) if 'line' in m}


def match_key(m):
    return (m.get('line'), m.get('pattern'))


def merge_two(dst, src):
    """把 src finding 合并进 dst:matches 去重并集、source 合并、severity 取高"""
    seen = {match_key(m) for m in dst['matches']}
    for m in src['matches']:
        if match_key(m) not in seen:
            dst['matches'].append(m)
            seen.add(match_key(m))
    dst['matches'].sort(key=lambda m: (m.get('line') is None, m.get('line', 0), m.get('pattern', '')))
    sources = set(dst['source'].split('+')) | set(src['source'].split('+'))
    dst['source'] = '+'.join(sorted(sources))
    if SEV_ORDER.get(src['severity'], 9) < SEV_ORDER.get(dst['severity'], 9):
        dst['severity'] = src['severity']
        dst['rule_id'] = src['rule_id']
        dst['rule_name'] = src['rule_name']


def merge_findings(base_findings, custom_findings):
    """合并两轮 findings,返回 (merged_list, n_merged)"""
    merged = []
    n_merged = 0
    # 按 (文件, 规则族) 分组,组内按行号重叠做传递归并
    groups = {}
    for f in list(base_findings) + list(custom_findings):
        groups.setdefault((f['file'], family_of(f['rule_id'])), []).append(f)

    for (_file, _fam), flist in groups.items():
        clusters = []   # 每个 cluster: {'finding': ..., 'lines': set()}
        for f in flist:
            lines = match_lines(f)
            if lines:
                hit = [c for c in clusters if c['lines'] & lines]
            else:
                hit = [c for c in clusters if not c['lines']]   # path 型:同文件同族即合并
            if not hit:
                clusters.append({'finding': f, 'lines': set(lines)})
                continue
            dst = hit[0]
            merge_two(dst['finding'], f)
            dst['lines'] |= lines
            n_merged += 1
            for c in hit[1:]:       # f 桥接了多个 cluster,一并归并
                merge_two(dst['finding'], c['finding'])
                dst['lines'] |= c['lines']
                clusters.remove(c)
                n_merged += 1
        merged.extend(c['finding'] for c in clusters)

    merged.sort(key=lambda x: (SEV_ORDER.get(x['severity'], 9), x['rule_id'], x['file']))
    return merged, n_merged


def load_findings(path, source):
    with open(path, encoding='utf-8') as f:
        data = json.load(f)
    findings = []
    for fd in data.get('findings', []):
        fd = dict(fd)
        fd['source'] = source
        fd['verdict'] = {'status': 'pending'}
        findings.append(fd)
    return data, findings


def main(argv=None):
    ap = argparse.ArgumentParser(description='合并两轮扫描结果,生成带 pending verdict 的 risk-report.json')
    ap.add_argument('target', nargs='?', default='.', help='目标目录(默认当前目录)')
    ap.add_argument('-b', '--base', default=None,
                    help='基线扫描结果(默认 <目标目录>/.risk_out/scan-base.json)')
    ap.add_argument('-c', '--custom', default=None,
                    help='补充扫描结果(默认 <目标目录>/.risk_out/scan-custom.json,不存在则跳过)')
    ap.add_argument('-o', '--output', default=None,
                    help='输出路径(默认 <目标目录>/.risk_out/risk-report.json)')
    ap.add_argument('-n', '--note', default=None, help='补充规则的制定依据一句话(记入 scan_passes)')
    args = ap.parse_args(argv)

    target = os.path.abspath(args.target)
    out_dir = os.path.join(target, '.risk_out')
    base_path = args.base or os.path.join(out_dir, 'scan-base.json')
    custom_path = args.custom or os.path.join(out_dir, 'scan-custom.json')
    output = args.output or os.path.join(out_dir, 'risk-report.json')

    if not os.path.isfile(base_path):
        print(f'错误: 基线扫描结果不存在 {base_path}', file=sys.stderr)
        return 1
    if args.custom and not os.path.isfile(custom_path):
        print(f'错误: 指定的补充扫描结果不存在 {custom_path}', file=sys.stderr)
        return 1

    base_data, base_findings = load_findings(base_path, 'base')
    scan_passes = [{'rules': os.path.basename(base_path),
                    'version': base_data.get('rules_version'),
                    'findings': len(base_findings)}]

    custom_findings = []
    if os.path.isfile(custom_path):
        custom_data, custom_findings = load_findings(custom_path, 'custom')
        pass_info = {'rules': os.path.basename(custom_path),
                     'version': custom_data.get('rules_version'),
                     'findings': len(custom_findings)}
        if args.note:
            pass_info['note'] = args.note
        scan_passes.append(pass_info)

    merged, n_merged = merge_findings(base_findings, custom_findings)

    report = {
        'target': target,
        'scan_passes': scan_passes,
        'summary': {'pending': len(merged)},
        'findings': merged,
    }
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    with open(output, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f'合并完成: 基线 {len(base_findings)} 条 + 补充 {len(custom_findings)} 条,'
          f'去重合并 {n_merged} 条 -> 共 {len(merged)} 条(全部 pending)')
    print(f'输出: {output}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
