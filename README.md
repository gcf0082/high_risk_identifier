# high_risk_identifier

高风险操作识别与审计的 agent 技能:规则驱动的正则扫描器 + 四轮审计工作流(扫描 → 审核 → 动态补规则二扫 → 整合),技能定义见 [SKILL.md](SKILL.md)。

## 安装

```bash
pip install -r requirements.txt   # 仅依赖 PyYAML>=5.4
```

## 扫描器用法

```bash
python scripts/scan.py <目标目录> [-o 输出.json] [-r rules.yaml] \
    [--min-severity high|medium|low] [-e py,java] [-p "**/src/**"] \
    [-x "**/test/**"] [-C N] [-w 8]
# 默认输出 <目标目录>/.risk_out/scan_result.json
```

- `-e` 只扫指定后缀(与规则取交集,丢弃项有 stderr 告警);`-p` 只扫路径匹配 glob 的文件
- `-x` 叠加排除路径;`-C N` 每条命中附带前后 N 行上下文;`-w` 并行进程数

## 辅助脚本

- `scripts/infer_excludes.py <目标目录>` — 从扫描结果推断 test/CI/三方件等噪声路径,生成 `.risk_out/exclude_paths.txt`
- `scripts/merge_reports.py <目标目录>` — 合并基线/补充两轮扫描结果,生成带 pending verdict 的 `risk-report.json`
- `scripts/annotate.py risk-report.json verdicts.json` — 校验并回填审核结论,重排 findings、更新 summary
- `scripts/list_scan_results.py [scan_result.json]` — 提取命中文件列表

## 产出目录

```
<目标目录>/.risk_out/
├── scan-base.json / scan-custom.json   # 两轮扫描结果
├── exclude_paths.txt                   # 推断排除路径
├── rules-custom.yaml                   # 动态补充规则
├── verdicts.json                       # 审核结论
└── risk-report.json                    # 最终整合报告
```

## 测试

```bash
python -m unittest discover tests
```
