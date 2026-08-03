#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
annotate.py — 把 agent 审核结论(verdicts.json)回填进 risk-report.json

verdicts.json 格式:
  [{"file": "src/a.py", "line": 42, "rule_id": "HR-COMMAND-EXEC",
    "status": "confirmed|suspicious|false_positive",
    "reason": "判定理由", "context": "调用链等补充"}]

行为:
  - 校验 status 枚举与必填字段;按 file + line + 规则族(rule_id 前两段)定位 finding
  - 有任何一条无法匹配或非法,全部错误列出并退出 1,不写文件(防止手写 JSON 串行后报告失真)
  - 全部合法才写回:按 confirmed -> suspicious -> false_positive -> pending 重排,更新 summary

用法:
  python annotate.py risk-report.json verdicts.json [-o 输出.json]
  不带 -o 时原地更新 risk-report.json
"""
import argparse
import json
import os
import sys

VALID_STATUS = {'confirmed', 'suspicious', 'false_positive'}
STATUS_ORDER = {'confirmed': 0, 'suspicious': 1, 'false_positive': 2, 'pending': 3}
SEV_ORDER = {'high': 0, 'medium': 1, 'low': 2}


def family_of(rule_id):
    """规则族:rule_id 前两段,如 HR-COMMAND-EXEC -> HR-COMMAND"""
    parts = rule_id.split('-', 2)
    return '-'.join(parts[:2]) if len(parts) >= 2 else rule_id


def main(argv=None):
    ap = argparse.ArgumentParser(description='把 verdicts.json 的审核结论回填进 risk-report.json')
    ap.add_argument('report', help='risk-report.json 路径')
    ap.add_argument('verdicts', help='agent 填写的 verdicts.json 路径')
    ap.add_argument('-o', '--output', default=None, help='输出路径(默认原地更新 report)')
    args = ap.parse_args(argv)

    for p in (args.report, args.verdicts):
        if not os.path.isfile(p):
            print(f'错误: 文件不存在 {p}', file=sys.stderr)
            return 1

    with open(args.report, encoding='utf-8') as f:
        report = json.load(f)
    with open(args.verdicts, encoding='utf-8') as f:
        verdicts = json.load(f)
    if not isinstance(verdicts, list):
        print('错误: verdicts.json 必须是 JSON 数组', file=sys.stderr)
        return 1

    # 按 (文件, 规则族) 建索引
    index = {}
    for fd in report.get('findings', []):
        index.setdefault((fd['file'], family_of(fd['rule_id'])), []).append(fd)

    # 先全量校验并定位,有任何错误都不写文件
    errors = []
    planned = []    # (finding, verdict)
    for i, v in enumerate(verdicts):
        tag = f'verdicts[{i}]'
        if not isinstance(v, dict):
            errors.append(f'{tag}: 不是对象')
            continue
        missing = [k for k in ('file', 'line', 'rule_id', 'status') if k not in v]
        if missing:
            errors.append(f'{tag}: 缺少字段 {missing}')
            continue
        if v['status'] not in VALID_STATUS:
            errors.append(f"{tag}: status 非法 {v['status']!r},可选 {sorted(VALID_STATUS)}")
            continue
        cands = index.get((v['file'], family_of(v['rule_id'])), [])
        target = next((fd for fd in cands
                       if any(m.get('line') == v['line'] for m in fd.get('matches', []))), None)
        if target is None:
            errors.append(f"{tag}: 未匹配到 finding(file={v['file']} line={v['line']} "
                          f"rule={v['rule_id']}),请核对行号/规则族")
            continue
        verdict = {'status': v['status']}
        if v.get('reason'):
            verdict['reason'] = v['reason']
        if v.get('context'):
            verdict['context'] = v['context']
        planned.append((target, verdict))

    if errors:
        print(f'错误: {len(errors)} 条 verdict 无法回填,未做任何修改:', file=sys.stderr)
        for e in errors:
            print(f'  {e}', file=sys.stderr)
        return 1

    for fd, verdict in planned:
        fd['verdict'] = verdict

    # 重排:confirmed -> suspicious -> false_positive -> pending,同级内 severity -> 规则 -> 文件
    findings = report.get('findings', [])
    findings.sort(key=lambda x: (
        STATUS_ORDER.get(x.get('verdict', {}).get('status', 'pending'), 9),
        SEV_ORDER.get(x['severity'], 9),
        x['rule_id'], x['file']))

    summary = {}
    for fd in findings:
        st = fd.get('verdict', {}).get('status', 'pending')
        summary[st] = summary.get(st, 0) + 1
    report['summary'] = summary

    output = args.output or args.report
    with open(output, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f'回填完成: {len(planned)} 条 verdict -> {output}')
    print(f'summary: {summary}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
