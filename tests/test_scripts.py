#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""infer_excludes / merge_reports / annotate 三个流程脚本的单元测试"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scripts'))
import annotate  # noqa: E402
import infer_excludes  # noqa: E402
import merge_reports  # noqa: E402


class ScriptsTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def write(self, rel, content):
        full = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, 'w', encoding='utf-8') as f:
            f.write(content)
        return full

    def write_json(self, rel, obj):
        full = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, 'w', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False)
        return full

    def read_json(self, path):
        with open(path, encoding='utf-8') as f:
            return json.load(f)


def scan_json(files):
    """构造最小扫描结果:每个文件一条 content finding"""
    return {
        'rules_version': 't1',
        'findings': [
            {'rule_id': 'HR-COMMAND-EXEC', 'rule_name': '命令执行', 'severity': 'high',
             'match_type': 'content', 'file': fp,
             'matches': [{'line': 1, 'pattern': r'os\.system\(', 'text': 'os.system("ls")'}]}
            for fp in files
        ],
    }


class TestInferExcludes(ScriptsTestBase):
    def run_infer(self, files, extra_files=None):
        for rel, content in (extra_files or {}).items():
            self.write(rel, content)
        scan_path = self.write_json('.risk_out/scan_result.json', scan_json(files))
        out = os.path.join(self.root, '.risk_out', 'exclude_paths.txt')
        rc = infer_excludes.main([self.root, '-i', scan_path, '--no-ask'])
        globs = []
        if os.path.isfile(out):
            with open(out, encoding='utf-8') as f:
                globs = [ln.strip() for ln in f if ln.strip()]
        return rc, globs, out

    def test_path_features(self):
        rc, globs, _ = self.run_infer(['src/main.py', 'test/test_x.py', 'mock/m.py', 'ci/p.py'])
        self.assertEqual(rc, 0)
        self.assertIn('**/test/**', globs)
        self.assertIn('**/mock/**', globs)
        self.assertIn('**/ci/**', globs)
        self.assertNotIn('src/main.py', globs)

    def test_content_feature_dir_merged(self):
        files = {
            'app/checks/a.py': 'import unittest\nclass T(unittest.TestCase):\n    pass\n',
            'app/checks/b.py': 'import unittest\nclass U(unittest.TestCase):\n    pass\n',
        }
        rc, globs, _ = self.run_infer(list(files), files)
        self.assertEqual(rc, 0)
        self.assertIn('app/checks/**', globs)

    def test_content_feature_single_file_below_threshold(self):
        files = {'app/checks/a.py': 'import unittest\nclass T(unittest.TestCase):\n    pass\n'}
        rc, globs, out = self.run_infer(list(files), files)
        self.assertEqual(rc, 3)               # 不足 MIN_DIR_HITS,不生成
        self.assertFalse(os.path.exists(out))

    def test_no_cluster_no_file(self):
        files = {'src/a.py': 'print("hello")\n', 'src/b.py': 'x = 1\n'}
        rc, globs, out = self.run_infer(list(files), files)
        self.assertEqual(rc, 3)
        self.assertFalse(os.path.exists(out))

    def test_missing_input(self):
        rc = infer_excludes.main([self.root, '-i', os.path.join(self.root, 'nope.json')])
        self.assertEqual(rc, 1)


def base_scan():
    return {
        'rules_version': '4.0',
        'findings': [
            {'rule_id': 'HR-COMMAND-EXEC', 'rule_name': '命令执行', 'severity': 'high',
             'match_type': 'content', 'file': 'src/a.py',
             'matches': [{'line': 10, 'pattern': r'os\.system\(', 'text': 'os.system("ls")'}]},
            {'rule_id': 'HR-FILE-DELETE', 'rule_name': '删除文件', 'severity': 'high',
             'match_type': 'content', 'file': 'src/c.py',
             'matches': [{'line': 3, 'pattern': 'shutil\\.rmtree', 'text': 'shutil.rmtree(d)'}]},
        ],
    }


def custom_scan():
    return {
        'rules_version': 'custom-1',
        'findings': [
            # 与基线同文件同行同族 -> 应合并
            {'rule_id': 'HR-COMMAND-NCE-CALL', 'rule_name': 'NCE 命令调用', 'severity': 'high',
             'match_type': 'content', 'file': 'src/a.py',
             'matches': [{'line': 10, 'pattern': 'NceCmd\\.run', 'text': 'NceCmd.run(c)'}]},
            # 不同文件 -> 独立保留
            {'rule_id': 'HR-NCE-UPLOAD', 'rule_name': 'NCE 上传', 'severity': 'high',
             'match_type': 'content', 'file': 'src/b.py',
             'matches': [{'line': 5, 'pattern': 'nce_upload', 'text': 'nce_upload(f)'}]},
        ],
    }


class TestMergeReports(ScriptsTestBase):
    def run_merge(self, extra=None):
        b = self.write_json('.risk_out/scan-base.json', base_scan())
        c = self.write_json('.risk_out/scan-custom.json', custom_scan())
        out = os.path.join(self.root, '.risk_out', 'risk-report.json')
        argv = [self.root, '-b', b, '-c', c, '-o', out] + (extra or [])
        rc = merge_reports.main(argv)
        return rc, self.read_json(out) if rc == 0 else None

    def test_merge_dedup_same_line_same_family(self):
        rc, report = self.run_merge()
        self.assertEqual(rc, 0)
        self.assertEqual(len(report['findings']), 3)     # 4 条去重合并 1 条
        merged = next(f for f in report['findings'] if f['file'] == 'src/a.py')
        self.assertEqual(merged['source'], 'base+custom')
        pats = {m['pattern'] for m in merged['matches']}
        self.assertEqual(pats, {r'os\.system\(', 'NceCmd\\.run'})
        self.assertEqual(merged['verdict'], {'status': 'pending'})

    def test_sources_and_skeleton(self):
        rc, report = self.run_merge(extra=['-n', '补充 NCE 内部命令 API'])
        self.assertEqual(report['summary'], {'pending': 3})
        self.assertEqual(len(report['scan_passes']), 2)
        self.assertEqual(report['scan_passes'][0]['version'], '4.0')
        self.assertEqual(report['scan_passes'][1]['note'], '补充 NCE 内部命令 API')
        by_file = {f['file']: f for f in report['findings']}
        self.assertEqual(by_file['src/b.py']['source'], 'custom')
        self.assertEqual(by_file['src/c.py']['source'], 'base')

    def test_base_only_when_custom_missing(self):
        b = self.write_json('.risk_out/scan-base.json', base_scan())
        out = os.path.join(self.root, '.risk_out', 'risk-report.json')
        rc = merge_reports.main([self.root, '-b', b,
                                 '-c', os.path.join(self.root, '.risk_out', 'scan-custom.json'),
                                 '-o', out])
        # 显式指定但不存在的 custom 应报错
        self.assertEqual(rc, 1)
        # 不显式指定时,约定路径不存在则跳过
        rc = merge_reports.main([self.root, '-b', b, '-o', out])
        self.assertEqual(rc, 0)
        report = self.read_json(out)
        self.assertEqual(len(report['scan_passes']), 1)
        self.assertEqual(len(report['findings']), 2)


class TestAnnotate(ScriptsTestBase):
    def make_report(self):
        b = self.write_json('.risk_out/scan-base.json', base_scan())
        out = os.path.join(self.root, '.risk_out', 'risk-report.json')
        self.assertEqual(merge_reports.main([self.root, '-b', b, '-o', out]), 0)
        return out

    def run_annotate(self, report_path, verdicts):
        v = self.write_json('.risk_out/verdicts.json', verdicts)
        return annotate.main([report_path, v])

    def test_annotate_ok_reorders_and_summarizes(self):
        report_path = self.make_report()
        verdicts = [
            {'file': 'src/c.py', 'line': 3, 'rule_id': 'HR-FILE-DELETE',
             'status': 'confirmed', 'reason': '路径来自入参', 'context': 'X.run() <- REST'},
            {'file': 'src/a.py', 'line': 10, 'rule_id': 'HR-COMMAND-EXEC',
             'status': 'false_positive', 'reason': '写死常量'},
        ]
        self.assertEqual(self.run_annotate(report_path, verdicts), 0)
        report = self.read_json(report_path)
        self.assertEqual(report['summary'], {'confirmed': 1, 'false_positive': 1})
        # confirmed 在前,false_positive 在后
        statuses = [f['verdict']['status'] for f in report['findings']]
        self.assertEqual(statuses, ['confirmed', 'false_positive'])
        v = report['findings'][0]['verdict']
        self.assertEqual(v['reason'], '路径来自入参')
        self.assertEqual(v['context'], 'X.run() <- REST')

    def test_family_match_across_rule_ids(self):
        # verdict 的 rule_id 与 finding 不同但同族,也应匹配
        report_path = self.make_report()
        verdicts = [{'file': 'src/a.py', 'line': 10, 'rule_id': 'HR-COMMAND-NCE-CALL',
                     'status': 'suspicious'}]
        self.assertEqual(self.run_annotate(report_path, verdicts), 0)
        report = self.read_json(report_path)
        self.assertEqual(report['summary'], {'suspicious': 1, 'pending': 1})

    def test_invalid_status_rejected_no_write(self):
        report_path = self.make_report()
        before = self.read_json(report_path)
        verdicts = [{'file': 'src/a.py', 'line': 10, 'rule_id': 'HR-COMMAND-EXEC',
                     'status': 'yes'}]
        self.assertEqual(self.run_annotate(report_path, verdicts), 1)
        self.assertEqual(self.read_json(report_path), before)   # 未做任何修改

    def test_unmatched_line_rejected(self):
        report_path = self.make_report()
        verdicts = [{'file': 'src/a.py', 'line': 999, 'rule_id': 'HR-COMMAND-EXEC',
                     'status': 'confirmed'}]
        self.assertEqual(self.run_annotate(report_path, verdicts), 1)


if __name__ == '__main__':
    unittest.main()
