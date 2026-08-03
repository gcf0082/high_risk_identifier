#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
infer_excludes.py — 从扫描结果推断疑似低价值路径,生成 exclude_paths.txt

按 SKILL.md 第 1.5 步的判定表,对 findings 涉及的文件做两级推断:
  - 路径特征:命中已知 test/CI/三方件/噪声目录模式的,直接归并成对应 glob
  - 内容特征:采样文件前 4KB,匹配测试框架/License 头等特征的,
    按父目录聚合(同一目录 >=2 个命中文件才归并成 `<目录>/**`,避免误排正常目录)

输出:每行一个 glob 写入 <目标目录>/.risk_out/exclude_paths.txt,并打印各类命中数量与全部路径。
退出码:0 正常生成;3 无可推断的聚集路径(不生成空文件);1 输入错误。

用法:
  python infer_excludes.py [目标目录] [-i scan_result.json] [-o exclude_paths.txt] [--no-ask]
"""
import argparse
import fnmatch
import json
import os
import re
import sys

SAMPLE_BYTES = 4096          # 内容特征采样长度
MIN_DIR_HITS = 2             # 内容特征按目录归并的最小命中文件数

# 路径特征:(类别, [glob ...]),命中即输出对应 glob
PATH_FEATURES = [
    ('测试代码', ['**/test/**', '**/tests/**', '**/__tests__/**', '**/testing/**', '**/fixtures/**']),
    ('CI/构建', ['**/.github/workflows/**', '**/ci/**', '**/build/**', '**/.gradle/**',
                 '**/target/**', '**/Jenkinsfile*']),
    ('三方件', ['**/vendor/**', '**/third_party/**', '**/node_modules/**', '**/dist/**']),
    ('其他噪声', ['**/mock/**', '**/example/**', '**/examples/**', '**/demo/**', '**/.git/**']),
]

# 内容特征:(类别, 正则),对采样内容 search
CONTENT_FEATURES = [
    ('测试代码', re.compile(r'@test|pytest\.mark|describe\(|it\(|unittest\.TestCase', re.IGNORECASE)),
    ('CI/构建', re.compile(r'github.*workflow|jenkinsfile|gitlab.*ci', re.IGNORECASE)),
    ('三方件', re.compile(r'Copyright.*(?:MIT|Apache|GPL|BSD|LGPL)'
                          r'|(?:MIT|Apache|GPL|BSD|LGPL)\s+License', re.IGNORECASE | re.DOTALL)),
]


def path_match(rel, pat):
    """与 scan.py 排除逻辑一致:兼容根级目录"""
    return fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch('/' + rel, pat)


def infer(scan_json, target):
    """推断排除路径,返回 (excludes, stats, content_dirs)
    excludes: 有序去重的 glob 列表
    stats:    类别 -> 命中文件数
    content_dirs: 内容特征归并出的目录命中数(目录 -> 文件数)
    """
    with open(scan_json, encoding='utf-8') as f:
        data = json.load(f)
    files = sorted({fd['file'] for fd in data.get('findings', [])})

    excludes = []
    stats = {}
    path_hit = set()

    # --- 路径特征 ---
    for cat, pats in PATH_FEATURES:
        cat_files = set()
        for pat in pats:
            hit = [rel for rel in files if path_match(rel, pat)]
            if hit:
                cat_files.update(hit)
                if pat not in excludes:
                    excludes.append(pat)
        if cat_files:
            stats[cat] = stats.get(cat, 0) + len(cat_files)
            path_hit.update(cat_files)

    # --- 内容特征(只检查未被路径特征覆盖的文件) ---
    dir_hits = {}        # 父目录 -> 命中文件集合
    for rel in files:
        if rel in path_hit:
            continue
        full = os.path.join(target, rel)
        try:
            with open(full, 'rb') as f:
                sample = f.read(SAMPLE_BYTES)
        except OSError:
            continue
        text = sample.decode('utf-8', errors='replace')
        for cat, rx in CONTENT_FEATURES:
            if rx.search(text):
                stats[cat] = stats.get(cat, 0) + 1
                parent = os.path.dirname(rel)
                if parent:
                    dir_hits.setdefault(parent, set()).add(rel)
                break   # 一个文件只归入第一个命中的类别

    content_dirs = {}
    for parent in sorted(dir_hits):
        if len(dir_hits[parent]) >= MIN_DIR_HITS:
            glob = f'{parent}/**'
            content_dirs[parent] = len(dir_hits[parent])
            if glob not in excludes:
                excludes.append(glob)

    return excludes, stats, content_dirs


def main(argv=None):
    ap = argparse.ArgumentParser(description='从扫描结果推断疑似低价值路径,生成 exclude_paths.txt')
    ap.add_argument('target', nargs='?', default='.', help='被扫描的目标目录(默认当前目录)')
    ap.add_argument('-i', '--input', default=None,
                    help='扫描结果 JSON(默认 <目标目录>/.risk_out/scan_result.json)')
    ap.add_argument('-o', '--output', default=None,
                    help='输出路径(默认 <目标目录>/.risk_out/exclude_paths.txt)')
    ap.add_argument('--no-ask', action='store_true',
                    help='直接写入结果不询问(脚本本身非交互,供 SKILL.md 流程显式声明)')
    args = ap.parse_args(argv)

    target = os.path.abspath(args.target)
    scan_json = args.input or os.path.join(target, '.risk_out', 'scan_result.json')
    output = args.output or os.path.join(target, '.risk_out', 'exclude_paths.txt')

    if not os.path.isfile(scan_json):
        print(f'错误: 扫描结果不存在 {scan_json}', file=sys.stderr)
        return 1

    excludes, stats, content_dirs = infer(scan_json, target)

    if not excludes:
        print('未发现可推断的聚集路径(test/CI/三方件等),不生成 exclude_paths.txt')
        return 3

    print('--- 各类命中文件数 ---')
    for cat, n in stats.items():
        print(f'  {cat}: {n}')
    if content_dirs:
        print('--- 内容特征归并的目录(>=%d 个命中文件) ---' % MIN_DIR_HITS)
        for d, n in content_dirs.items():
            print(f'  {d}: {n}')

    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    with open(output, 'w', encoding='utf-8') as f:
        f.write('\n'.join(excludes) + '\n')

    print(f'--- 推断排除路径({len(excludes)} 条)-> {output} ---')
    for g in excludes:
        print(g)
    return 0


if __name__ == '__main__':
    sys.exit(main())
