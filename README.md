# AAB Compare

`aab-compare` 是一个完全在本机运行的 Android App Bundle 查重工具。日常只需传入两个 AAB；工具优先使用已登记的严格构建归属证据，找不到有效 provenance 时自动切换到 AAB 启发式归属。

默认结果只面向应用产出内容，分别比较：

- 业务代码
- 长方法
- 图片
- 其他资源
- Manifest
- Assets

AndroidX、Google、Kotlin/KotlinX、JetBrains、Facebook 等公开库，以及常见 SDK 和工具生成内容会被过滤。六项结果独立展示，不生成容易掩盖差异的综合分。原八维全包算法仍可通过 `--mode legacy` 显式使用。

## 环境要求

- Python 3.11+
- Java 17+
- 首次安装外部工具时可访问 GitHub Releases

项目锁定 Androguard 4.1.4、JADX 1.5.6 和 Bundletool 1.18.3。JADX 与 Bundletool 的下载地址和 SHA-256 固化在代码中，不会在运行时追随 `latest`。

## 安装

```bash
git clone https://github.com/HolinB/aab-comparison-tool.git
cd aab-comparison-tool
uv sync --extra dev --python 3.11
```

比较时会自动安装并校验缺失的 JADX 和 Bundletool。也可提前执行 `uv run aab-compare tools install`，并用 `uv run aab-compare tools status` 检查状态。

如果默认用户缓存目录不可写，可显式指定：

```bash
uv run aab-compare tools install --tool-dir .aab-compare-cache/tools
```

## 使用

```bash
uv run aab-compare app-a.aab app-b.aab
```

分析完成后打开：

```text
aab-compare-output/app-a-vs-app-b/report.md
```

默认报告写入 `./aab-compare-output/app-a-vs-app-b/`。重复运行同一对 AAB 时，只有带合法 `.aab-compare-output` marker 的工具管理目录会被自动刷新；非工具目录和符号链接会被拒绝。可用 `-o` 覆盖默认位置。

直接比较会按以下顺序选择分析策略：

1. 精确匹配本机 provenance registry，并重新验证 ownership TOML、AAB、R8 mapping、resource merger 和 lock 后，执行严格 owned 分析。
2. 没有匹配记录或严格证据失效时，执行 AAB 启发式 owned 分析，并在报告顶部标明置信边界。

普通双文件比较不会运行 Gradle 或改写 provenance。需要严格自有归属时，先显式准备一次：

```bash
cp ownership.example.toml my-projects.ownership.toml
# 编辑 my-projects.ownership.toml 后执行：
uv run aab-compare prepare my-projects.ownership.toml
uv run aab-compare /absolute/path/to/app-a.aab /absolute/path/to/app-b.aab
```

`prepare` 只执行每侧明确配置的单个 `prepare_task`；没有该字段的一侧不会执行 Gradle。任务必须是形如 `:app:bundleRelease` 的绝对 Gradle 任务路径，且不接受额外参数或 shell 语法。准备成功后只写 deterministic provenance lock 和本机 registry 记录，不立即执行比较。

任务完成后，工具会对两侧同时生成 deterministic provenance lock。锁固定 artifact SHA-256、实际采用的 embedded 或 disk R8 mapping 原始 SHA-256、最终 resource merger 以及分析实际读取的各模块 package merger SHA-256；存在与目标 artifact 精确匹配的 hardening verification report 时也会绑定其哈希。锁位于 ownership TOML 明确指定的项目外部路径，不依赖报告输出目录，也不会写入 Android 项目或 AAB。

Registry 只用于定位 ownership 配置，不作为归属证据。严格分析仍会重新验证全部 lock 内容；任何 artifact、实际 mapping、merger、配置路径或 variant 变化都会切换为带告警的启发式结果。修改 embedded mapping 被采用时未使用的磁盘 mapping 不影响验证。

显式使用旧八维模式：

```bash
uv run aab-compare app-a.aab app-b.aab --mode legacy -o output/legacy-comparison
```

离线、禁用画像缓存并覆盖工具自己创建的旧结果：

```bash
uv run aab-compare app-a.aab app-b.aab \
  --offline --no-cache \
  --tool-dir .aab-compare-cache/tools \
  --cache-dir .aab-compare-cache/profiles
```

旧命令 `aab-compare compare LEFT RIGHT --ownership-config CONFIG` 和 `--prepare-provenance` 暂时保留兼容，并在 stderr 输出弃用提示。

完整的安装方式、严格归属配置、参数表、结果解读、故障排查和自动化示例见 [详细使用说明](docs/USAGE.md)。

## 项目结构

```text
.
├── src/aab_compare/       # CLI、分析器、归属、评分与报告实现
├── tests/                 # 单元测试和集成测试
├── docs/USAGE.md          # 完整使用手册
├── aab-compare.example.toml
├── ownership.example.toml
├── pyproject.toml
└── uv.lock
```

## 输出

```text
output/comparison/
├── report.md
├── data/analysis.json
├── data/schema.json
├── evidence/
│   ├── business_code/*.txt
│   ├── long_methods/*.txt
│   ├── images/*.png
│   └── ...
└── logs/run.json
```

- `report.md`：owned 模式下为六项独立分数、双向覆盖率、归因、Top 证据和告警，不产生综合分或等级。
- `analysis.json`：Schema v3 的稳定画像与结果；owned 模式的 `aggregate` 固定为 `null`，`ownership.strategy` 标明 `strict_provenance` 或 `heuristic_aab`。
- `schema.json`：用于校验结构化结果的 JSON Schema Draft 2020-12 定义。
- `run.json`：缓存命中、工具路径和本次运行信息；这些易变信息不会写入稳定报告。
- 代码证据：DEX 指纹详情；JADX 能输出对应类时附双方源码片段。
- 图片证据：从双方 AAB 直接提取并生成成对缩略图。

## Legacy 评分

| 维度 | 权重 |
|---|---:|
| 业务代码 | 35% |
| 长方法 | 15% |
| Manifest | 10% |
| 资源结构 | 10% |
| 图片 | 8% |
| 依赖 | 5% |
| Assets / Native | 10% |
| 构建结构 | 7% |

等级为：`0–29 低`、`30–54 中`、`55–74 高`、`75–100 极高`。方法指纹忽略类名、方法名、寄存器号和数值常量，结合操作码 shingles、控制流、Android/JDK API 调用与常量类别。第三方 Maven group、常见 SDK 包名和生成类会从业务代码中剥离；可通过配置中的 `business_prefixes` 恢复误分类的业务包。

## 分析配置

使用 `--config aab-compare.example.toml` 加载 TOML。所有八个权重最终必须合计 100；未写字段继承默认值。

常用参数：

- `long_method_min_instructions`：长方法最低 DEX 指令数，默认 100。
- `min_method_similarity`：方法最终匹配阈值，默认 0.70。
- `max_findings_per_dimension`：每维写入报告的最大证据数，默认 50。
- `third_party_prefixes` / `business_prefixes`：DEX descriptor 包前缀，如 `Lcom/example/`。
- `[archive_limits]`：输入大小、解压总量、单条目、条目数和压缩比限制。

## 所有权配置

复制 `ownership.example.toml`、填写真实路径后，使用 `aab-compare prepare MY_CONFIG.ownership.toml` 加载并登记独立的所有权 TOML。Ownership Schema 2 在顶层必须声明：

- `provenance_lock`：相对 ownership TOML 或绝对的锁文件路径；必须位于两个 Android 项目根目录之外，且不能与 ownership TOML 或任一 AAB 路径重叠。已有的非 provenance lock 文件不会被覆盖。

每侧必须声明：

- `project_root`：项目根目录，必须存在。
- `source_roots`：相对项目根目录的 Android 源码根目录。
- `variant`：lower camel-case Android variant。
- `artifact_output`：最终 AAB，可为项目内相对路径或绝对路径。
- `prepare_task`：可选；仅由显式 `prepare` 或兼容入口 `--prepare-provenance` 执行。
- `owned_generated_roots`：明确批准计入自有范围的生成代码、资源或 Manifest 根。

## 退出码

| 退出码 | 含义 |
|---:|---|
| 0 | 分析和报告生成完成；高相似度本身不会导致失败 |
| 2 | 输入、配置或输出目录错误 |
| 3 | 外部工具安装或校验失败 |
| 4 | DEX 核心分析不完整，报告仅供诊断 |
| 5 | 未预期内部错误 |

## 验证

```bash
uv run pytest -q
uv run pytest -m integration
uv run ruff check .
uv run mypy src
```

## 安全与限制

- AAB 和反编译结果不会上传；所有分析均在本机完成。
- ZIP 路径穿越、符号链接、重复条目、压缩炸弹和过大条目会在读取前被拒绝。
- 严格 owned 比较会先验证 lock，再在临时目录中固定两侧 AAB 和所有 provenance 输入；分析、缓存、Bundletool 与 JADX 均消费已验证快照，运行结束后自动删除临时副本。
- `prepare` 通过已验证并持续持有的文件描述符刷新现有 lock，路径身份变化或写入错误会拒绝并尽力回滚；该过程假定没有同一 UID 的恶意并发写入，进程崩溃或断电仍可能留下可通过重新 prepare 恢复的无效 lock。
- 启发式 owned 会过滤已知公共包、依赖元数据、生成类、公共资源前缀和 SDK Assets，但不能证明所有未知内容均为自有产出。
- DEX 指纹评分不依赖 JADX。JADX 对部分混淆类失败时，代码分仍有效，但相应源码证据可能缺失。
- 依赖识别和相似度阈值属于启发式分析，不能直接替代人工或法律鉴定。
- 操作者应确保拥有对目标 AAB 进行反编译和比较的合法授权。
