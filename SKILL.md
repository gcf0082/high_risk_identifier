---
name: high-risk-scan
description: 扫描指定目录,识别疑似高风险操作并输出审计报告
---

# 高风险点识别与审计

对目标目录做四轮工作:**扫描 → 审核确认 → 动态补规则二扫 → 整合**。

不要拿到扫描结果就直接罗列给用户——未经审核的正则命中噪声很大,价值在于你的判断。

## 工具

`scripts/` 下(均支持 `-h` 查看完整参数):

- `scan.py` — 规则驱动扫描器,基础规则 `rules.yaml`
  `python scripts/scan.py <目标目录> [-e py,java] [-p "**/src/**"] [-x "**/test/**"] [-C 3] [-r 规则.yaml] [-o 输出.json] [-w 8]`
  (`-e` 只扫指定后缀、`-p` 只扫匹配路径、`-x` 追加排除、`-C N` 命中带前后 N 行上下文)
- `infer_excludes.py` — 从扫描结果推断 test/CI/三方件等应排除的路径
  `python scripts/infer_excludes.py <目标目录>`(默认读 `.risk_out/scan_result.json`,写 `.risk_out/exclude_paths.txt`)
- `merge_reports.py` — 合并 base/custom 两轮结果,按规则族去重,生成带 `verdict: pending` 的报告骨架
  `python scripts/merge_reports.py <目标目录> [-n "补充规则依据"]`
- `annotate.py` — 校验并回填 verdicts.json,按 confirmed → suspicious → false_positive 重排
  `python scripts/annotate.py <报告.json> <verdicts.json>`

所有产出放在**目标目录下的 `.risk_out/`**(规则已排除该目录,不会被二次扫描)。

## 第 1 步:基线扫描

```bash
python scripts/scan.py <目标目录> -w 8
# 默认输出 <目标目录>/.risk_out/scan_result.json,改名为 scan-base.json
```

然后运行 `infer_excludes.py <目标目录>` 推断排除路径(test/CI/三方件等),
有聚集结果时与用户确认后加 `-x` 二扫降噪;分散无聚集(退出码 3)则跳过。

## 第 2 步:审核确认(核心步骤)

按 severity 从高到低,逐条 finding 打开对应文件、读命中行**前后 20-30 行**上下文,逐条判定:

- `confirmed`:上下文确认是真实风险
- `suspicious`:无法完全确认(如看不到调用链),但值得人工再看
- `false_positive`:明确是误报,理由写清楚

**确认真阳性的关键**:危险动作的输入(命令参数、删除路径、目标地址、凭据值)
是否可被外部控制。输入是硬编码常量、内部固定值、占位符,或命中的是注释/日志文案/
死代码/测试代码,则不是真阳性。测试、生成代码、文档目录里的命中一般不高于 `suspicious`。

审核不完时:high 必须全部审完,medium 可抽样审并在报告注明未审数量。

## 第 3 步:动态补充规则二扫

先看懂项目:语言、框架、业务域、命令模板格式、内部 RPC 风格。据此写
`.risk_out/rules-custom.yaml`(格式同 `rules.yaml`),再扫一轮并同样审核。

**硬性约束(违反就失去补充的意义):**
- 只允许 `severity: high`
- 只加**项目特异**的模式(内部框架危险 API、产品特有命令前缀/模板);不要重复通用规则
- 每条正则必须带上下文锚点,宁可漏不可滥;逐条验证能编译;能配 `path` 组就不用宽内容正则

确实没有值得补的特异模式就跳过,在报告里说明原因——不要为了补而补。

## 第 4 步:整合输出

```bash
python scripts/merge_reports.py <目标目录> [-n "补充规则依据一句话"]   # 生成 risk-report.json 骨架
# agent 把第 2/3 步审核结论写入 .risk_out/verdicts.json:
# [{"file":..., "line":..., "rule_id":..., "status":..., "reason":..., "context":...}]
python scripts/annotate.py <目标目录>/.risk_out/risk-report.json <目标目录>/.risk_out/verdicts.json
```

merge 自动按规则族去重(同文件同行 base+custom 合并),annotate 校验后回填 verdict
并按 confirmed → suspicious → false_positive 排序。

最后在对话里给用户简短结论:confirmed 几条、最值得关注的是哪几条(文件:行 + 一句话原因)、
补了什么自定义规则、还有多少 medium 未审。细节都在 JSON 里,不要在对话里贴大段结果。
