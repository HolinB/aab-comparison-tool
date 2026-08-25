# AAB Compare 详细使用说明

本文说明如何安装、运行和解读 `aab-compare`。工具只在本机读取 AAB 和可选的 Android 构建归属文件，不会把输入、源码、反编译结果或报告上传到网络。首次下载 JADX 和 Bundletool 时除外。

## 1. 环境准备

必需环境：

- macOS 或 Linux；Windows 建议通过 WSL 使用
- Python 3.11 或更高版本
- Java 17 或更高版本
- `uv`
- 首次安装外部工具时可访问 GitHub Releases

检查环境：

```bash
python3 --version
java -version
uv --version
```

克隆项目并创建环境：

```bash
git clone https://github.com/HolinB/aab-comparison-tool.git
cd aab-comparison-tool
uv sync --extra dev --python 3.11
uv run aab-compare --version
```

若只需要命令而不参与开发，也可以从项目根目录安装为独立工具：

```bash
uv tool install .
aab-compare --version
```

后文默认使用无需全局安装的 `uv run aab-compare`。若使用 `uv tool install`，去掉命令前的 `uv run` 即可。

## 2. 最简单的比较方式

```bash
uv run aab-compare /path/to/app-a.aab /path/to/app-b.aab
```

默认输出目录为：

```text
./aab-compare-output/app-a-vs-app-b/
```

指定输出目录：

```bash
uv run aab-compare app-a.aab app-b.aab -o output/my-comparison
```

工具会依次执行以下选择：

1. 查询本机 provenance registry 是否存在这两个 AAB 的精确有序路径记录。
2. 若记录存在，重新验证 ownership 配置、AAB SHA-256、provenance lock、R8 mapping 和资源合并证据。
3. 全部验证通过时使用严格归属策略 `strict_provenance`。
4. 没有记录或任一严格证据失效时，自动使用启发式策略 `heuristic_aab`。

普通双文件比较不会运行 Gradle，也不会修改 Android 项目或输入 AAB。

## 3. 分析策略

### 3.1 AAB 启发式归属

直接比较两个未登记的 AAB 时会自动使用启发式归属。它从 Manifest、DEX、资源和依赖元数据推断应用代码与资源，并过滤：

- Android、AndroidX
- Google 与 Firebase
- Kotlin、KotlinX、JetBrains
- Facebook
- Airbnb、Square、Tencent、NetEase、ObjectBox、Sentry 等常见 SDK
- BuildConfig、ViewBinding、DataBinding、KAPT 等工具生成类
- 已知公共资源前缀、SDK Manifest 组件和 SDK Assets 路径

`business_prefixes` 可显式保留被公共规则误判的业务包。启发式结果会降低置信度并在报告中明确告警，因为仅凭 AAB 无法证明每个未知文件的源码归属。

强制使用启发式策略：

```bash
uv run aab-compare app-a.aab app-b.aab --mode heuristic
```

### 3.2 严格构建归属

严格策略适合只比较团队实际编写或明确批准生成的内容。先复制并修改示例：

```bash
cp ownership.example.toml my-projects.ownership.toml
```

配置结构：

```toml
schema_version = 2
provenance_lock = "cache/provenance.lock.json"

[left]
project_root = "/absolute/path/to/project-a"
source_roots = ["app/src", "base/src"]
variant = "demoRelease"
artifact_output = "app/build/outputs/bundle/demoRelease/app-demo-release.aab"
prepare_task = ":app:bundleDemoRelease"
owned_generated_roots = [
  "app/build/generated/java/generateDemoReleaseJunkCode",
  "app/build/generated/res/generateDemoReleaseJunkCode",
]

[right]
project_root = "/absolute/path/to/project-b"
source_roots = ["app/src", "base/src"]
variant = "release"
artifact_output = "/absolute/path/to/prebuilt-b.aab"
owned_generated_roots = []
```

字段含义：

| 字段 | 说明 |
|---|---|
| `provenance_lock` | 锁文件位置。必须在两个 Android 项目根目录之外，且不能覆盖 TOML 或 AAB |
| `project_root` | Android 项目根目录，必须存在 |
| `source_roots` | 相对项目根目录的自有模块源码根 |
| `variant` | lower camel-case Android variant，例如 `demoRelease` |
| `artifact_output` | 该侧最终 AAB，可使用项目内相对路径或绝对路径 |
| `prepare_task` | 可选。只有显式执行 `prepare` 时才运行的单个绝对 Gradle 任务 |
| `owned_generated_roots` | 明确批准计入自有范围的生成 Java/Kotlin、资源或 Manifest |

准备并登记：

```bash
uv run aab-compare prepare my-projects.ownership.toml
```

`prepare` 只运行配置中明确写出的 `prepare_task`。任务必须类似 `:app:bundleDemoRelease`，不接受额外命令参数或 shell 语法。没有 `prepare_task` 的一侧只验证现有 AAB。

随后仅传两个配置中 `artifact_output` 对应的规范路径：

```bash
uv run aab-compare \
  /absolute/path/to/app-a.aab \
  /absolute/path/to/app-b.aab
```

Registry 只负责找到 ownership TOML，不属于归属证据。每次严格比较都会重新验证 lock；AAB、mapping、resource merger、配置路径或 variant 变化后应重新执行 `prepare`。

## 4. 六项结果如何解读

Owned 模式输出以下六项，不计算综合分或等级：

| 维度 | 比较内容 |
|---|---|
| 业务代码 | DEX 方法指纹、调用特征、控制流与常量类别 |
| 长方法 | 达到指令数阈值的方法级相似度 |
| 图片 | 位图感知哈希、尺寸和内容证据 |
| 其他资源 | layout、drawable XML、values 及资源结构 |
| Manifest | 自有组件、属性和重复节点 |
| Assets | 自有或候选 Assets 的路径与内容 |

每项包含：

- `score`：0 到 100；没有可比较的 owned 输入时为 `N/A`，不会错误显示 100
- 左到右覆盖率：A 的内容在 B 中被覆盖的比例
- 右到左覆盖率：B 的内容在 A 中被覆盖的比例
- `confidence`：当前归属证据与分析覆盖度，不等同于相似度
- Top 证据：最重要的匹配项及可用的源码或图片证据
- warnings：缺失工具、归属不确定或分析降级信息

高分表示对应维度具有较高技术相似度，但不能单独证明代码来源、侵权事实或法律责任。启发式报告尤其需要结合人工复核。

## 5. 输出目录

```text
aab-compare-output/app-a-vs-app-b/
├── report.md
├── data/
│   ├── analysis.json
│   └── schema.json
├── evidence/
│   ├── business_code/
│   ├── long_methods/
│   ├── images/
│   └── ...
└── logs/
    └── run.json
```

- `report.md`：主要人工报告。
- `analysis.json`：Schema v3 稳定结果；owned 模式的 `aggregate` 为 `null`。
- `schema.json`：JSON Schema Draft 2020-12。
- `evidence/`：DEX/JADX 文本、资源和成对图片缩略图。
- `run.json`：工具路径、缓存状态和耗时等非确定性运行信息。

直接双文件入口会自动刷新包含合法 `.aab-compare-output` marker 的默认或自定义输出目录。工具拒绝覆盖普通目录、符号链接和未知文件；需要保留旧报告时，请改用新的 `-o` 路径。

```bash
uv run aab-compare app-a.aab app-b.aab -o output/my-comparison-v2
```

## 6. 常用参数

| 参数 | 用途 |
|---|---|
| `-o, --output PATH` | 指定输出目录 |
| `--mode auto` | 默认；严格 provenance 可用时使用严格策略，否则启发式 |
| `--mode heuristic` | 强制启发式 owned 分析 |
| `--mode legacy` | 使用原全 AAB 八维算法和综合分 |
| `--config FILE` | 加载分析阈值、包过滤和归档限制 TOML |
| `--offline` | 禁止下载工具；缺少固定工具时以退出码 3 结束 |
| `--no-cache` | 不读写 AAB 画像缓存 |
| `--overwrite` | 兼容 `compare` 子命令使用；刷新已有且由本工具管理的输出目录 |
| `--jobs N` | 设置 JADX 并行任务数，必须大于 0 |
| `--cache-dir PATH` | 指定画像缓存目录 |
| `--tool-dir PATH` | 指定 JADX/Bundletool 目录 |

兼容入口仍可暂时使用：

```bash
uv run aab-compare compare app-a.aab app-b.aab \
  --ownership-config my-projects.ownership.toml
```

它会输出弃用提示。新流程应使用一次 `prepare` 加日常双 AAB 命令。

## 7. 外部工具

项目固定使用：

- Androguard 4.1.4
- JADX 1.5.6
- Bundletool 1.18.3

在线比较会自动安装并校验缺失的 JADX 与 Bundletool。也可预先安装：

```bash
uv run aab-compare tools install
uv run aab-compare tools status
```

指定独立工具目录：

```bash
uv run aab-compare tools install --tool-dir .aab-compare-cache/tools
uv run aab-compare app-a.aab app-b.aab \
  --tool-dir .aab-compare-cache/tools \
  --offline
```

下载使用固定 release URL，并校验代码中固化的 SHA-256。目录不是由本工具管理时不会被替换。

## 8. 分析配置

复制默认示例：

```bash
cp aab-compare.example.toml my-analysis.toml
uv run aab-compare app-a.aab app-b.aab --config my-analysis.toml
```

常用字段：

- `long_method_min_instructions`：长方法最低 DEX 指令数。
- `min_method_similarity`：方法匹配阈值。
- `max_findings_per_dimension`：每个维度写入报告的最大证据数。
- `third_party_prefixes`：额外排除的 DEX descriptor 包前缀。
- `business_prefixes`：明确保留的业务 DEX descriptor 包前缀。
- `[archive_limits]`：输入大小、解压总量、单条目、条目数和压缩比限制。

包前缀使用 DEX descriptor 形式，例如：

```toml
third_party_prefixes = ["Lcom/vendor/sdk/"]
business_prefixes = ["Lcom/example/myapp/"]
```

Legacy 模式下八个权重必须合计为 100；未写字段继承默认值。

## 9. 确定性重跑

需要验证稳定结果时，先确保固定版本工具已安装，再运行：

```bash
uv run aab-compare app-a.aab app-b.aab \
  --offline --no-cache
```

相同 AAB、配置、工具版本与 provenance 输入应生成字节一致的 `report.md` 和 `data/analysis.json`。`logs/run.json` 包含耗时和缓存路径，不属于确定性结果。

## 10. 退出码

| 退出码 | 含义 |
|---:|---|
| 0 | 报告生成完成；高相似度不会导致命令失败 |
| 2 | AAB、配置、provenance 或输出目录错误 |
| 3 | 外部工具安装或校验失败 |
| 4 | DEX 核心分析不完整，报告仅供诊断 |
| 5 | 未预期内部错误 |

脚本中可直接判断退出码：

```bash
if uv run aab-compare app-a.aab app-b.aab --offline; then
  echo "comparison completed"
else
  echo "comparison failed: $?"
fi
```

## 11. 常见问题

### 离线模式提示缺少工具

先在可联网环境执行 `tools install`，确认 `tools status` 中 `verified` 为 `true`，再使用同一个 `--tool-dir` 运行离线比较。

### 明明执行过 prepare，却进入启发式模式

检查报告中 `diagnostics.selection` 和终端告警。常见原因包括：

- 传入路径不是 registry 登记的规范路径，即使文件内容相同也不会命中。
- AAB 内容或 SHA-256 已变化。
- mapping、resource merger、hardening verification 或 ownership TOML 已变化。
- provenance lock 被移动、损坏或过期。

修正配置后重新执行 `prepare`。临时复制到新路径的 AAB 按设计会进入启发式模式。

### 输出目录拒绝覆盖

不要手动复用包含其他文件的目录。改用新的 `-o` 路径。直接双文件入口会自动刷新本工具生成且 marker 完整的目录；普通目录和符号链接始终会被拒绝。

### JADX 失败是否影响代码评分

DEX 指纹评分不依赖 JADX。JADX 失败会减少可读源码证据，但不会自动使 DEX 指纹分失效。若 Androguard 无法完成 DEX 核心解析，命令返回退出码 4。

### 如何验证结果 JSON

```bash
uv run python -m jsonschema \
  -i aab-compare-output/app-a-vs-app-b/data/analysis.json \
  aab-compare-output/app-a-vs-app-b/data/schema.json
```

## 12. 开发验证

```bash
uv run pytest -q
uv run pytest -m integration
uv run ruff check .
uv run mypy src
uv build
```

测试会使用合成 AAB 和临时目录；仓库不应包含真实 AAB、Android 项目源码、provenance lock、registry、缓存或生成报告。

## 13. 安全边界

- 输入 AAB 以只读方式处理，分析在本机临时目录中完成。
- 严格分析会先验证 lock，再固定 AAB 与 provenance 输入的快照。
- ZIP 路径穿越、符号链接、重复条目、压缩炸弹和超限条目会被拒绝。
- 工具只自动刷新带合法 marker 的输出和工具目录。
- 启发式过滤降低公开库干扰，但不能替代源码 provenance。
- 使用者应确保拥有对目标 AAB 反编译和比较的合法授权。
