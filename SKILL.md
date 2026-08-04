---
name: high-risk-scan
description: 扫描指定目录,识别疑似高风险操作并输出结果 JSON
---

# 高风险点扫描

执行扫描脚本，按 `scripts/rules.yaml` 的规则扫描目标目录，全局配置读取 `scripts/config.yaml`，结果写入 `<目标目录>/.risk_out/scan_result.json`。

## 用法

```bash
python scripts/scan.py <目标目录>
```

不带参数时扫描当前目录。可选参数：`-o` 输出路径、`-c` 配置文件、`-r` 规则文件、`--min-severity`（high/medium/low，默认 high）、`-e` 只扫指定后缀（如 `py,java`）、`-p` 只扫匹配路径（glob）、`-x` 排除路径（glob）。

## 规则配置

`scripts/rules.yaml` 中每条规则包含若干 `match` 组，每个组支持：

- `ext`：文件后缀列表（必需）。
- `content`：逐行匹配文件内容的正则列表。
- `path`：匹配文件相对路径的正则列表。
- `paths`：glob 路径白名单，文件路径必须命中其中之一该组才生效。
- `exclude_paths`：glob 路径黑名单，文件路径命中任一该组即不生效。
