---
name: high-risk-scan
description: 扫描指定目录,识别疑似高风险操作并输出审计报告
---

# 高风险点识别与审计

对目标目录做四轮工作:**扫描 → 审核确认 → 动态补规则二扫 → 整合**。
扫描脚本和基础规则在本目录的 `scripts/` 下:`scripts/scan.py`、`scripts/rules.yaml`。

## 总流程

1. **基线扫描**:用现成规则跑出原始命中
2. **审核确认**:按优先级(high → medium)逐条读代码上下文,判定真阳性/存疑/误报
3. **动态补扫**:理解项目技术栈与业务特征,写一份自定义规则(只允许 high、必须低误报),再扫一轮并同样审核
4. **整合**:两轮结果合并去重,输出带确认状态的增强 JSON

不要拿到扫描结果就直接罗列给用户——未经审核的正则命中噪声很大,价值在于你的判断。

## 准备工作区

所有产出放在**目标目录下的 `.risk_out/`**(扫描器默认输出目录,规则已排除该目录,不会被二次扫描):

```
<目标目录>/.risk_out/
├── scan-base.json        # 基线扫描结果
├── rules-custom.yaml     # 动态补充规则(第 3 步产出)
├── scan-custom.json      # 补充扫描结果
└── risk-report.json      # 最终整合报告
```

## 第 1 步:基线扫描

```bash
python scripts/scan.py <目标目录> [--min-severity medium] [-e py,java,go] [-p "**/src/**"] [-x "**/test/**"] [-w 8]
# 默认输出 <目标目录>/.risk_out/scan_result.json,改名/移动为 scan-base.json
```

**参数说明:**

| 参数 | 说明 |
|------|------|
| `-e` / `--ext` | 只扫描指定后缀的文件(逗号分隔),与规则取交集。例如:`-e py,java,go` 只扫这三种后缀 |
| `-p` / `--path` | 只扫描路径匹配指定 glob 的文件(逗号分隔),与规则取交集。例如:`-p "**/src/**,**/core/**"` |
| `-x` / `--exclude` | 排除指定路径(glob,逗号分隔),可与 rules.yaml 中的 `exclude_paths` 叠加。例如:`-x "**/test/**,**/mock/**"` |
| `--min-severity` | 覆盖规则文件的最低 severity,默认 high |
| `-w N` | 并行 worker 数,默认 CPU 核数 |

**典型用法:**
```bash
# 全量扫描,输出 medium+high
python scripts/scan.py . -w 8

# 只扫 Python/Java,排除测试目录
python scripts/scan.py . -e py,java -x "**/test/**" -w 8

# 只扫 Go,在 src/ 和 core/ 目录下,排除 test/
python scripts/scan.py . -e go -p "**/src/**,**/core/**" -x "**/test/**" -w 8
```

默认扫到 high 级别。medium 量大时可以先只看 high,但 JSON 里要留全量,审核按优先级来。

## 第 1.5 步:推断排除（降低误报）

扫完后根据路径特征和文件内容，自动识别疑似 test/CI 构建/三方件路径，写入 `<目标目录>/.risk_out/exclude_paths.txt`（**自动生成，无需询问用户**）。生成后默认询问用户是否用其进一步排除后二扫。

**推断依据：**

| 类型 | 路径特征 | 内容特征 |
|------|----------|----------|
| 测试代码 | `**/test/**`、`**/__tests__/**`、`**/testing/**`、`**/fixtures/**` | `@test`、`pytest.mark`、`describe(`、`it(`、`unittest.TestCase` |
| CI/构建 | `**/.github/workflows/**`、`**/ci/**`、`**/build/**`、`**/.gradle/**`、`**/target/**`、`**/Jenkinsfile*` | `github.*workflow`、`jenkinsfile`、`gitlab.*ci` |
| 三方件 | `**/vendor/**`、`**/third_party/**`、`**/node_modules/**`、`**/dist/**` | `Copyright` + `All rights reserved`/`Proprietary`、`LGPL`/`GPL`/`BSD`/`MIT`/`Apache` License |
| 其他噪声 | `**/mock/**`、`**/example/**`、`**/demo/**`、`**/.git/**` | — |

**判断逻辑：** 路径命中上表任意一条，或文件内容（采样前 4KB）匹配内容特征正则，即视为疑似目标。

**操作流程：**

1. 首轮扫描完成，执行 `list_scan_results.py` 获取路径列表和总数
2. 根据数量、分布、路径聚集特征**智能判断**是否生成 `exclude_paths.txt`（如：大量命中集中在 test/mock/build 等目录时生成；命中分散在全项目各处则跳过）；文件多或判断复杂时调用 agent 分析后再生成
3. 若生成，`exclude_paths.txt` 每行一个 glob 路径（如 `**/test/**`），不含注释、空行或其他内容。显示总条数和全部路径
4. 确认则二扫；否则跳过。也可手动指定排除路径（glob 格式，逗号分隔）
5. 若判断不需要生成或 txt 为空，询问是否手动指定排除路径
6. 使用 `--no-ask` 参数可跳过询问，直接用推断路径二扫

**典型场景：**
- 首轮 1201 条 high，识别出 300+ 条 test 命中 → 确认二扫后降到 800 条，审核量大幅减少
- 已知项目结构较干净，可直接 `--no-ask` 跳过询问快速输出结果

## 第 2 步:审核确认(核心步骤)

按 severity 从高到低,逐条 finding 打开对应文件、读命中行**前后 20-30 行**上下文,判断后写入 verdict。

**判定标准按规则族区分:**

| 规则族 | 确认真阳性的关键点 | 常见误报 |
|---|---|---|
| 命令执行(HR-COMMAND-EXEC) | 真的在拼/执行命令;参数是否可被外部输入控制 | 只是变量名像、注释、日志文案、从未被调用的死代码 |
| 脚本引擎/表达式执行 | 引擎 eval 的输入来自外部(报文、配置、REST 入参) | 引擎输入是硬编码常量 |
| 文件删除/覆盖 | 删除路径是否可被外部控制、是否无校验递归删 | 删除自己创建的临时目录且路径固定 |
| 上传/下载/网络 | 真的发生外发/拉取;目标地址是否硬编码内部地址 | 内部微服务间正常调用 |
| JNDI | lookup 的地址是否可被外部(如日志内容)控制 | 内部固定 JNDI 名 |
| 硬编码凭据 | 值像真实凭据(长度、复杂度、非占位符) | 占位符(xxx/example/changeme)、测试桩、从变量引用 |
| 敏感文件访问/入库 | 真的读私钥/凭据文件,或仓库里真有这些文件 | 读的是自己生成的临时密钥 |

**每条 verdict 三选一:**
- `confirmed`:上下文确认是真实风险
- `suspicious`:无法完全确认(如看不到调用链),但值得人工再看
- `false_positive`:明确是误报,理由写清楚

测试代码、生成代码、文档目录里的命中,一般不高于 `suspicious`,说明理由。
审核不完时:high 必须全部审完,medium 可以抽样审并在报告里注明未审核数量。

## 第 3 步:动态补充规则二扫

先看懂项目:主要语言、框架、业务域(如华为 NCE/MAE 网管)、命令模板格式、配置文件类型、内部 RPC/接口风格。据此写 `rules-custom.yaml`,格式与 `rules.yaml` 完全一致(先读它的文件头注释了解 schema)。

**硬性约束(违反就失去补充的意义):**
- 只允许 `severity: high`
- 只加**项目特异**的模式:内部框架的危险 API、产品特有的命令前缀/模板、项目里实际出现的危险写法泛化;不要把 rules.yaml 里已有的通用模式换个写法再加一遍
- 每条正则必须够精确:带上下文锚点(类名、包名、产品前缀、独特语法),宁可漏不可滥;写完用 `python3 -c "import re; re.compile(...)"` 逐条验证能编译
- 能配 `path` 组就别用宽内容正则(路径匹配天然低误报)

然后跑第二轮并同样做审核:

```bash
python scripts/scan.py <目标目录> -r <目标目录>/.risk_out/rules-custom.yaml -o <目标目录>/.risk_out/scan-custom.json --min-severity high [-e py,java] [-x "**/test/**"] -w 8
```

如果通读项目后确实没有值得补的特异模式,跳过这步,在报告里说明原因——不要为了补而补。

## 第 4 步:整合输出增强 JSON

合并两轮 findings 写入 `risk-report.json`,在扫描原始字段基础上为每条 finding 追加 `verdict`:

```json
{
  "target": "...",
  "scan_passes": [
    {"rules": "rules.yaml", "version": "3.5", "findings": 12},
    {"rules": "rules-custom.yaml", "findings": 2, "note": "补充规则的制定依据一句话"}
  ],
  "summary": {"confirmed": 5, "suspicious": 4, "false_positive": 5},
  "findings": [
    {
      "rule_id": "HR-COMMAND-EXEC",
      "rule_name": "...",
      "severity": "high",
      "match_type": "content",
      "file": "src/...",
      "matches": [{"line": 42, "pattern": "...", "text": "..."}],
      "source": "base",
      "verdict": {
        "status": "confirmed",
        "reason": "exec 的参数 cmd 直接来自 REST 入参,无校验",
        "context": "调用链:UploadController.run() <- REST /upload"
      }
    }
  ]
}
```

- `source`: `base`(基线规则)或 `custom`(动态补充规则)
- 去重:两轮命中同一文件同一行且规则族相同(如基线已有命令执行命中,补充规则又命中同一行),合并成一条,`source` 记 `base+custom`
- 排序:`confirmed` 在前,`suspicious` 次之,`false_positive` 最后;同级内按 severity

最后在对话里给用户一个简短结论:confirmed 几条、最值得关注的是哪几条(文件:行 + 一句话原因)、补了什么自定义规则、还有多少 medium 未审。细节都在 JSON 里,不要在对话里贴大段结果。
