#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 scan_result.json 中提取所有命中文件的路径列表和总数。

用法:
  python list_scan_results.py [scan_result.json]
  不带参数时默认找 <当前目录>/.risk_out/scan_result.json
"""
import json
import os
import sys


def list_results(json_path):
    if not os.path.isfile(json_path):
        print(f'错误: 文件不存在 {json_path}', file=sys.stderr)
        sys.exit(1)

    with open(json_path, encoding='utf-8') as f:
        data = json.load(f)

    findings = data.get('findings', [])
    files = sorted({f['file'] for f in findings})
    summary = data.get('summary', {})

    print(f'结果文件: {json_path}')
    print(f'总文件数: {len(files)}')
    print(f'总命中数: {len(findings)}')
    print(f'级别分布: {summary}')
    print()
    print('--- 文件路径列表 ---')
    for fp in files:
        print(fp)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        path = os.path.join(os.getcwd(), '.risk_out', 'scan_result.json')
    list_results(path)
