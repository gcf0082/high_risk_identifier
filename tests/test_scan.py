#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan.py 单元测试:规则编译、命中、豁免、CLI 告警、列号/上下文字段"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scripts'))
import scan  # noqa: E402

SCAN_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scripts', 'scan.py')

RULES_YAML = r'''
version: "t1"
severity_levels: [high, medium, low]
min_severity: high
case_sensitive: true
exclude_paths:
  - "**/excluded/**"
rules:
  - id: HR-COMMAND-EXEC
    name: 命令执行
    severity: high
    match:
      - ext: [py]
        content:
          - 'os\.system\('
          - '\beval\('
      - ext: [sh]
        path:
          - 'dangerous_.*'
  - id: HR-NETWORK-OPERATION
    name: 网络操作
    severity: medium
    match:
      - ext: [py]
        content:
          - 'requests\.'
'''


class ScanTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.rules_path = os.path.join(self.root, 'rules.yaml')
        with open(self.rules_path, 'w', encoding='utf-8') as f:
            f.write(RULES_YAML)

    def write(self, rel, content):
        full = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        mode = 'wb' if isinstance(content, bytes) else 'w'
        with open(full, mode) as f:
            f.write(content)
        return full

    def load_config(self, min_sev=None, context=0):
        cfg = scan.compile_rules(self.rules_path, min_sev)
        cfg['context_lines'] = context
        scan.CONFIG = cfg
        return cfg


class TestCompileRules(ScanTestBase):
    def test_severity_filter_default_high(self):
        cfg = scan.compile_rules(self.rules_path)
        self.assertEqual([r['id'] for r in cfg['rules']], ['HR-COMMAND-EXEC'])

    def test_severity_filter_override_medium(self):
        cfg = scan.compile_rules(self.rules_path, 'medium')
        self.assertEqual([r['id'] for r in cfg['rules']],
                         ['HR-COMMAND-EXEC', 'HR-NETWORK-OPERATION'])

    def test_combined_regex_compiled(self):
        cfg = scan.compile_rules(self.rules_path)
        g = cfg['rules'][0]['groups'][0]
        self.assertIsNotNone(g['content_re'])
        self.assertTrue(g['content_re'].search('os.system("ls")'))
        self.assertFalse(g['content_re'].search('print("hi")'))

    def test_ext_index_built(self):
        cfg = scan.compile_rules(self.rules_path)
        self.assertIn('py', cfg['content_by_ext'])
        self.assertEqual(len(cfg['content_by_ext']['py']), 1)
        self.assertEqual(cfg['content_any'], [])


class TestScanFile(ScanTestBase):
    def test_content_hit_with_column(self):
        self.write('a.py', 'x = 1\n  os.system("ls")\n')
        self.load_config()
        findings = scan.scan_file((self.root, 'a.py'))
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f['rule_id'], 'HR-COMMAND-EXEC')
        self.assertEqual(f['match_type'], 'content')
        m = f['matches'][0]
        self.assertEqual(m['line'], 2)
        self.assertEqual(m['column'], 3)          # 'os.system' 起始列(1 起始)
        self.assertIn('pattern', m)
        self.assertIn('text', m)
        self.assertNotIn('context', m)            # 默认不带上下文

    def test_context_lines(self):
        self.write('a.py', 'l1\nl2\nos.system("ls")\nl4\nl5\n')
        self.load_config(context=1)
        findings = scan.scan_file((self.root, 'a.py'))
        m = findings[0]['matches'][0]
        self.assertEqual(m['line'], 3)
        ctx = m['context']
        self.assertEqual([c['line'] for c in ctx], [2, 3, 4])
        self.assertEqual(ctx[0]['text'], 'l2')

    def test_path_hit(self):
        self.write('dangerous_deploy.sh', '#!/bin/sh\necho hi\n')
        self.load_config()
        findings = scan.scan_file((self.root, 'dangerous_deploy.sh'))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['match_type'], 'path')
        self.assertEqual(findings[0]['matches'], [{'pattern': 'dangerous_.*'}])

    def test_shebang_line_exempted(self):
        # shebang 行内含 eval( 不应命中;第 3 行的 eval( 应命中且行号正确
        self.write('b.py', '#!/usr/bin/env python eval(\nx = 1\neval("1+1")\n')
        self.load_config()
        findings = scan.scan_file((self.root, 'b.py'))
        self.assertEqual(len(findings), 1)
        lines = [m['line'] for m in findings[0]['matches']]
        self.assertEqual(lines, [3])

    def test_binary_skipped(self):
        self.write('bin.py', b'\x00\x01os.system("ls")\x00')
        self.load_config()
        self.assertEqual(scan.scan_file((self.root, 'bin.py')), [])

    def test_ext_index_prefilter(self):
        # .sh 文件没有适用的 content 组,不应读内容也不应命中 py 规则
        self.write('run.sh', 'os.system("ls")\n')
        self.load_config()
        self.assertEqual(scan.scan_file((self.root, 'run.sh')), [])


class TestCli(ScanTestBase):
    def run_scan(self, *extra):
        out = os.path.join(self.root, 'out.json')
        cmd = [sys.executable, SCAN_PY, self.root, '-r', self.rules_path,
               '-o', out, '-w', '1', *extra]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(out, encoding='utf-8') as f:
            return json.load(f), proc

    def test_exclude_paths_applied(self):
        self.write('src/ok.py', 'os.system("ls")\n')
        self.write('excluded/bad.py', 'os.system("ls")\n')
        report, _ = self.run_scan()
        files = {f['file'] for f in report['findings']}
        self.assertEqual(files, {'src/ok.py'})
        self.assertGreaterEqual(report['excluded_files'], 1)

    def test_ext_empty_intersection_warns(self):
        self.write('a.py', 'os.system("ls")\n')
        report, proc = self.run_scan('-e', 'rb')
        self.assertIn('交集为空', proc.stderr)
        self.assertIn('rb', proc.stderr)
        self.assertEqual(report['scanned_files'], 0)

    def test_ext_partial_drop_warns(self):
        self.write('a.py', 'os.system("ls")\n')
        report, proc = self.run_scan('-e', 'py,rb')
        self.assertIn('已丢弃', proc.stderr)
        self.assertIn('rb', proc.stderr)
        self.assertEqual(report['scanned_files'], 1)

    def test_path_filter_used_directly(self):
        # '**/src/**' 不在规则的 paths 里,旧实现交集后会被丢空;现在应直接使用
        self.write('src/a.py', 'os.system("ls")\n')
        self.write('other/b.py', 'os.system("ls")\n')
        report, _ = self.run_scan('-p', '**/src/**')
        files = {f['file'] for f in report['findings']}
        self.assertEqual(files, {'src/a.py'})

    def test_path_filter_no_match_warns(self):
        self.write('a.py', 'os.system("ls")\n')
        report, proc = self.run_scan('-p', '**/nonexistent/**')
        self.assertIn('文件数为 0', proc.stderr)
        self.assertIn('-p', proc.stderr)
        self.assertEqual(report['scanned_files'], 0)

    def test_context_option_cli(self):
        self.write('a.py', 'l1\nos.system("ls")\nl3\n')
        report, _ = self.run_scan('-C', '1')
        m = report['findings'][0]['matches'][0]
        self.assertIn('context', m)
        self.assertEqual([c['line'] for c in m['context']], [1, 2, 3])


if __name__ == '__main__':
    unittest.main()
