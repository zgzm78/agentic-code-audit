# Agentic Code Audit 综合改进方案

## 1. 文档目标

本文档用于指导下一轮系统整改。它不是新增功能清单，而是针对最近 Exiv2 测试暴露出来的问题，重新收敛系统的工程目标、数据契约、LLM 参与方式、动态验证架构、Docker 运行模型和性能预算。

当前系统已经能跑通完整审计流程，但测试结果显示：

- 运行时间过长，单次 Exiv2 测试约 20 分钟。
- Finding 数量增加，但高质量源码漏洞很少。
- 配置类风险仍占据报告主体。
- C/C++ 源码候选多为弱规则命中，真实可验证漏洞少。
- Verification 大量 `blocked`，动态验证没有真正执行起来。
- Mining debug 数据部分不可信，无法准确解释候选过滤原因。
- LLM 已被引入为 MiningDirector，但还没有形成端到端“指挥闭环”。

下一轮目标是：让系统从“能跑完整流程”升级为“能在可控时间内产出可解释、高信号、可验证的源码漏洞线索”。

## 2. 当前问题总览

### 2.1 性能问题

最近一次 Exiv2 测试数据：

```text
dangerous_functions = 2758
program_slices = 160
candidates = 160
findings = 42
verification_attempts = 42
```

其中规则产生了大量危险点：

```text
rules anchors = 2692
semgrep anchors = 66
```

这说明当前瓶颈不是工具本身，而是规则过宽导致后续切片、候选、分类、验证和报告全部被放大。

### 2.2 结果质量问题

42 个 finding 中：

```text
supply_chain_config = 30
other / environment = 10
unsafe_memory_copy / source_code = 2
```

这说明：

- 配置风险仍然淹没源码漏洞。
- `other` 类型过多，说明类型归一化没有吃到规则和上下文事实。
- 真正进入源码动态验证队列的 finding 太少。

### 2.3 验证问题

所有 verification 都是 `blocked`：

```text
30 supply_chain_config -> static_blocked
10 other/environment -> should_verify_false_static_evidence
2 unsafe_memory_copy/source_code -> native_harness_or_static_blocked
```

真正应该动态验证的只有 2 个源码 finding，但它们 blocked 的原因是：

```text
Native PoC input generated, but no built CLI binary was found.
```

这说明动态验证链路还没有完成：

- native build 没有稳定启用或没有产出可执行文件。
- Verification 没有消费 MiningDirector 的验证策略。
- 非源码风险仍生成了大量 PoC/exploit 目录，造成报告噪声。

### 2.4 数据契约问题

发现了几类数据一致性问题：

- LLM 返回字符串 evidence 时被按字符拆分，显示成 `G | i | t | H`。
- candidate 出现 `valid=False` 但 `validity=valid` 的矛盾状态。
- `mining-debug.json` 中 `aggregation_output_count=0`，但实际有 42 个 finding。
- rule 的 `vuln_type` 没有稳定传递到 normalizer，导致 `std::copy`、`memcmp` 等被归成 `other`。

这些问题会让 UI、报告、debug 和后续策略判断都不可信。

## 3. 总体改进原则

### 3.1 先控噪，再增强能力

不要继续盲目增加工具和规则。工具越多，如果数据契约和过滤策略不严，噪声会指数级增加。

正确顺序：

```text
数据契约收紧
-> anchor 降噪
-> 类型归一化
-> 静态验证分层
-> TopK 动态验证
-> C/C++ 深度增强
```

### 3.2 LLM 做指挥，但不能替代事实

LLM 可以做：

- Mining 战术规划
- 关注目录选择
- 候选优先级排序
- 静态可达性解释
- 动态验证策略建议
- PoC 思路生成

LLM 不能直接决定：

- 最终漏洞类型
- 最终验证状态
- 工具事实
- 是否 verified
- 是否 exploitable

最终事实必须来自：

```text
工具输出 + 规则校验 + 结构化切片 + 真实执行证据 + Checker
```

### 3.3 验证必须分层

验证不应该直接从 finding 跳到 dynamic runtime。应拆成：

```text
StaticVerification -> DynamicVerification -> CheckerVerdict
```

只有静态验证认为合理、可达、有动态验证价值的源码 finding，才进入动态验证。

### 3.4 预算必须成为一等配置

一次审计任务必须有明确预算：

- 最大运行时间
- 最大工具时间
- 最大 anchor 数
- 最大 slice 数
- 最大 candidate 数
- 最大 finding 数
- 最大 LLM 调用数
- 最大动态验证数

没有预算的 agentic 流程不可控。

## 4. 改进目标

下一轮完成后应达到：

1. Exiv2 quick 模式运行时间控制在 5 分钟以内。
2. Exiv2 standard 模式运行时间控制在 8 到 12 分钟。
3. `.github/` 配置风险不再淹没源码漏洞。
4. Finding 类型全部来自内部标准枚举。
5. `valid / validity / invalid_reason` 不再矛盾。
6. `mining-debug.json` 能真实反映聚合、过滤和 finding 分布。
7. 非源码风险返回 `static_only`，不生成动态 PoC。
8. 动态验证只对 TopK 源码 finding 执行。
9. Verification 能消费 MiningDirector 的 build/runtime/PoC 策略。
10. blocked 必须带清晰原因，例如 `build_disabled`、`binary_not_found`、`missing_compiler`、`no_runtime_entry`。

## 5. 阶段一：性能预算与运行模式

### 5.1 新增运行模式

新增统一配置：

```text
AuditMode = quick | standard | deep
```

建议默认使用 `standard`。

### 5.2 预算配置

新增 `AuditBudget`：

```text
mode
max_total_seconds
max_tool_seconds
max_llm_calls
max_anchors
max_slices
max_candidates
max_findings
max_dynamic_verifications
enable_config_audit
enable_dependency_audit
enable_secret_audit
enable_native_build
```

建议值：

```text
quick:
  max_total_seconds: 300
  max_tool_seconds: 60
  max_llm_calls: 8
  max_anchors: 300
  max_slices: 40
  max_candidates: 40
  max_findings: 10
  max_dynamic_verifications: 1
  enable_config_audit: false

standard:
  max_total_seconds: 720
  max_tool_seconds: 180
  max_llm_calls: 20
  max_anchors: 800
  max_slices: 80
  max_candidates: 80
  max_findings: 20
  max_dynamic_verifications: 3
  enable_config_audit: true

deep:
  max_total_seconds: 1800
  max_tool_seconds: 600
  max_llm_calls: 60
  max_anchors: 2500
  max_slices: 200
  max_candidates: 200
  max_findings: 50
  max_dynamic_verifications: 10
  enable_config_audit: true
```

### 5.3 预算执行点

预算必须在以下位置生效：

- ToolPlanner 推荐工具数量
- ToolRunner 单工具超时
- DangerousFunctionLocator anchor 数量
- SliceAnalyzer slice 数量
- CandidateGenerator LLM batch 数量
- ClueAggregator 输出数量
- VulnerabilityClassifier finding 数量
- VerificationAgent 动态验证数量

### 5.4 验收标准

- quick 模式不会对 160 个 slice 做候选生成。
- quick 模式默认不跑配置类 audit。
- standard 模式中 `.github` finding 不超过报告主体的 30%。
- deep 模式才允许完整配置风险和大规模规则探索。

## 6. 阶段二：Mining 数据契约修复

### 6.1 统一列表字段解析

新增工具函数：

```python
def coerce_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)]
```

使用位置：

- `trigger_conditions`
- `evidence`
- `missing_checks`
- `assumptions`
- `artifact_refs`
- `tool_run_refs`

禁止出现按字符拆分 evidence 的情况。

### 6.2 Candidate 状态单一化

当前存在：

```text
valid=False
validity=valid
```

必须改成统一方法：

```python
candidate.mark_valid()
candidate.mark_invalid(reason)
```

或者只保留：

```text
validity = valid | invalid_candidate | rejected_by_static_verifier | false_positive
```

如果继续保留 `valid: bool`，必须保证它由 `validity` 派生，不允许手工分开修改。

### 6.3 保留规则事实

`DangerousFunction` 和 `ProgramSlice` 必须传递以下字段：

```text
rule_id
rule_vuln_type
anchor_kind
anchor_category
anchor_tool
anchor_confidence
```

CandidateGenerator 和 VulnerabilityTypeNormalizer 必须优先使用：

```text
tool rule id
rule_vuln_type
anchor_category
file_path
sink
LLM type
```

不能只靠 sink 重新猜类型。

### 6.4 修复 Mining Debug

`mining-debug.json` 必须由真实 `MiningResult` 生成，不能在 server 中构造假的 proxy。

需要保存：

```text
aggregated_candidates
strategy
budget
prefilter_stats
static_verification_stats
```

### 6.5 验收标准

- evidence 不再出现 `G | i | t | H`。
- candidate 不再出现 `valid=False && validity=valid`。
- `aggregation_output_count` 与实际聚合数量一致。
- `other` 类型比例显著下降。

## 7. 阶段三：Anchor 降噪与 C/C++ 规则收紧

### 7.1 Anchor 分域

所有 anchor 先分域：

```text
source_code
supply_chain_config
dependency
secret
environment
weak_signal
```

默认审计目标是源码漏洞时：

- `.github/` 进入配置风险队列。
- `docs/` 默认降权。
- `tests/` 默认降权。
- `samples/` 默认降权，但可作为验证样例。

### 7.2 C/C++ 规则收紧

以下规则不能单独生成高优先级 candidate：

- `array_index`
- `c_style_cast`
- `open`
- `mmap`
- `fopen`
- `new[]`
- `malloc`
- `free`
- `memcmp`
- `std::copy`

它们只能在满足组合条件时进入候选：

```text
source identified
sink args include source-derived variable
missing guard before sink
parser context matched
or tool corroboration exists
```

### 7.3 C/C++ 组合规则

新增组合判断：

```text
memcpy/memmove/std::copy + tainted size + missing bounds -> unsafe_memory_copy
memcmp + tainted buffer/length + missing bounds -> out_of_bounds_read
array index + tainted index + missing bounds -> out_of_bounds_read/write
offset + size arithmetic + unchecked overflow -> integer_overflow
cast/truncation + size/offset variable -> integer_overflow
```

### 7.4 Anchor 预过滤

在 SliceAnalyzer 之前执行：

```text
drop weak_signal if confidence < threshold
drop source_code anchors without function boundary unless tool evidence exists
drop config anchors if budget.enable_config_audit=false
rank anchors by domain, parser context, confidence, tool corroboration
take topK
```

### 7.5 验收标准

- Exiv2 `dangerous_functions` 不再默认达到 2700+。
- standard 模式 source_code slice 数量稳定在 60 到 100。
- `other/environment` finding 显著减少。

## 8. 阶段四：LLM 指挥官闭环

### 8.1 MiningDirector 合理性

让 LLM 作为指挥官是合理方向，但必须限制在策略层。

MiningDirector 输出：

```text
focus_directories
skip_patterns
priority_functions
parser_entries
taint_sources
tool_selections
build_attempt
harness_candidates
suggested_oracles
candidate_prioritization_rules
```

### 8.2 策略校验

LLM 输出必须经过规则校验：

- focus 目录必须存在。
- skip pattern 不能跳过整个源码目录。
- tool 必须可用或有 fallback。
- build_attempt 必须和项目画像一致。
- harness candidate 文件必须存在。
- oracle 必须来自白名单。

### 8.3 策略持久化

`AuditReport` 新增：

```text
mining_strategy
strategy_validation_notes
strategy_artifact_id
```

`mining-debug.json` 必须包含完整 strategy。

### 8.4 Director 影响范围

MiningDirector 必须实际影响：

- tool selection
- anchor ranking
- slice selection
- candidate prioritization
- verification planning

如果只是生成 rationale，不影响后续排序和验证，则不算完成。

### 8.5 验收标准

- Exiv2 策略能优先关注 `src/`、`app/`、parser/read/decode 路径。
- `.github/` 风险可被 director 降权或单独分组。
- 报告中能看到 Director 为什么选择这些路径。

## 9. 阶段五：验证架构重构

### 9.1 新验证状态机

Verification 改为：

```text
Finding
  -> StaticVerifier
  -> DynamicPlanner
  -> RuntimeManager
  -> EvidenceChecker
  -> VerificationResult
```

### 9.2 StaticVerifier

静态验证目标：判断 finding 是否合理、可达、值得动态验证。

输入：

```text
finding
candidate
program_slice
dangerous_function
tool_runs
artifacts
project_profile
mining_strategy
```

输出：

```text
static_status:
  plausible
  weak_static_proof
  likely_false_positive
  needs_more_context
  static_only
  blocked_static

reachability:
  reachable
  likely_reachable
  unknown
  unlikely

dynamic_eligible: true | false
reason
evidence_refs
rule_checks
llm_review
```

LLM 可以参与静态验证，但最终必须输出结构化 JSON，并由规则校验。

### 9.3 DynamicPlanner

只有满足以下条件才进入动态规划：

```text
risk_domain == source_code
static_status in {plausible, weak_static_proof}
dynamic_eligible == true
budget has dynamic verification slots
```

DynamicPlanner 输出：

```text
runtime_type:
  cpp_cli
  cpp_harness
  python_test
  node_test
  http_service
  library_harness
  static_only
  blocked

build_strategy:
  existing_binary
  cmake_build
  make_build
  meson_build
  no_build_possible

poc_strategy:
  malformed_file
  cli_arg
  unit_test
  harness
  http_request

oracle:
  asan_crash
  ubsan
  nonzero_exit
  stderr_marker
  output_diff
  timeout
```

### 9.4 RuntimeManager

RuntimeManager 只负责按 plan 执行，不负责判断漏洞真假。

执行约束：

- 默认 Docker sandbox。
- verification sandbox 不联网。
- build sandbox 可配置是否联网。
- 命令必须在 workdir 内。
- 超时、CPU、内存限制必须记录。
- stdout/stderr/exit_code 必须保存 artifact。

### 9.5 EvidenceChecker

Checker 只看真实证据：

```text
ASAN/UBSAN/Valgrind/crash
exit code
stdout/stderr marker
file diff/hash
HTTP oracle
static rule evidence
```

最终状态：

```text
verified
exploitable
partially_verified
not_reproducible
blocked
false_positive
uncertain
static_only
```

### 9.6 非源码风险处理

以下风险不进入动态验证：

```text
supply_chain_config
dependency_vulnerability
secret_leak
environment
other
```

它们返回：

```text
static_only
false_positive
uncertain
```

不要生成动态 PoC 目录，不要生成 native blocked。

### 9.7 验收标准

- 42 个 finding 不再全部生成 verification PoC 目录。
- 非源码风险显示为 `static_only`，不是 `blocked`。
- 源码 TopK finding 才执行 dynamic runtime。
- blocked 必须明确是 `build_disabled`、`binary_not_found`、`missing_tool`、`no_runtime_entry` 等。

## 10. 阶段六：Docker 与运行环境整理

### 10.1 当前镜像职责

当前 compose 应保持三类镜像：

```text
agentic-code-audit-backend:local
agentic-code-audit-frontend:local
agentic-code-audit-sandbox:local
```

职责：

```text
backend:
  FastAPI
  Agent orchestration
  SQLite/store
  report generation
  lightweight tools
  docker CLI

frontend:
  Vite/React UI

sandbox:
  heavy security/build/verification tools
  no network by default
```

### 10.2 建议拆分 sandbox 模式

当前 sandbox 同时承担分析、构建和验证，会带来冲突：

- 分析和验证希望无网络。
- 构建有时需要拉依赖。

建议逻辑上拆分：

```text
analysis_sandbox:
  network none
  run semgrep/cppcheck/clang-tidy/rg

build_sandbox:
  network optional
  run cmake/make/ninja/npm/pip/cargo
  use dependency cache

verification_sandbox:
  network none
  run PoC/checker
```

第一版不一定要拆三个镜像，可以先在 RuntimeManager 中用不同 Docker 参数启动临时容器。

### 10.3 镜像文档化

新增文档或 UI 面板展示：

```text
image name
container name
installed tools
network policy
mounted volumes
used by which stage
```

### 10.4 验收标准

- 用户能清楚知道工具在 backend 还是 sandbox。
- `/api/tools` 显示 host/backend 可用工具时，必须说明 sandbox tool availability。
- build 失败时能说明是 sandbox 无网络、缺依赖还是未启用 native build。

## 11. 阶段七：动态验证启动条件修复

### 11.1 native build 开关

修复 API 创建任务时忽略 `enable_native_build` 的问题。

要求：

```text
frontend -> TaskCreate.enable_native_build
server -> STORE.create_task(enable_native_build=payload.enable_native_build)
orchestrator -> VerificationAgent(auto_build_native=task.enable_native_build or settings)
```

### 11.2 Exiv2 CLI 识别

Recon/BuildManager 需要识别：

```text
exiv2 binary candidates
build/bin/exiv2
build/app/exiv2
bin/exiv2
```

如果没有 binary：

```text
if native_build_enabled:
  attempt build
else:
  blocked_reason = build_disabled
```

### 11.3 MiningDirector 验证建议接入

VerificationAgent 新增参数：

```python
verify(..., mining_strategy: MiningStrategy | None = None)
```

使用：

- `strategy.build_attempt`
- `strategy.harness_candidates`
- `strategy.suggested_oracles`
- `strategy.parser_entries`

### 11.4 验收标准

- Exiv2 若未启用 native build，blocked 原因是 `build_disabled`。
- Exiv2 若启用 native build 且构建成功，能执行至少一个 CLI/harness command。
- VerificationResult 中有真实 command/stdout/stderr/exit_code。

## 12. 阶段八：UI 与报告改进

### 12.1 UI 分组

Finding 列表按风险域分组：

```text
源码漏洞
供应链配置风险
依赖风险
Secret
环境/弱静态线索
```

默认展开源码漏洞，折叠配置风险。

### 12.2 Debug 面板

任务详情新增 Mining Debug：

```text
anchor count by tool
anchor count by domain
candidate valid/invalid
invalid reason topN
aggregation input/output
finding type/domain distribution
verification queue count
budget usage
LLM call count
```

### 12.3 Verification 面板

按三阶段展示：

```text
静态验证
动态验证
Checker 判定
```

不要只显示一个 `blocked`。

### 12.4 验收标准

- 用户能直接看出为什么动态验证没启动。
- 用户能直接看出哪些 finding 只是配置风险。
- 用户能直接看出耗时花在工具、LLM、验证还是报告。

## 13. 推荐开发顺序

### 第一批：必须先修

1. `coerce_str_list`
2. candidate 状态一致性
3. rule fact 传递到 normalizer
4. mining-debug 使用真实 MiningResult
5. 非源码风险返回 `static_only`
6. budget quick/standard/deep

目标：让结果和 debug 可信，运行时间可控。

### 第二批：验证架构落地

1. `StaticVerifier`
2. `DynamicPlanner`
3. `RuntimeManager` 只执行 plan
4. `EvidenceChecker` 统一 verdict
5. `VerificationResult` 增加 static/dynamic/checker 三段字段
6. native build 开关贯通

目标：让动态验证真正启动，blocked 原因可解释。

### 第三批：MiningDirector 闭环

1. 策略持久化
2. 策略校验
3. 策略影响 anchor/slice/candidate 排序
4. 策略影响 VerificationPlan
5. 历史 verification feedback 参与下一轮策略

目标：LLM 作为指挥官，而不是旁路建议器。

### 第四批：C/C++ 深度增强

1. 规则组合化
2. C++ source/sink/guard 关系
3. ctags/libclang 函数边界
4. 函数内 def-use
5. size/offset/index 数据流
6. sanitizer build 和 CLI/harness 验证

目标：提升真实 C/C++ 漏洞发现能力。

## 14. 测试计划

### 14.1 单元测试

- 字符串 evidence 不被拆字符。
- candidate 状态不可矛盾。
- normalizer 使用 rule vuln_type。
- `supply_chain_config` 返回 `static_only`。
- `other/environment` 不进入动态验证。
- `source_code` TopK 才动态验证。
- quick budget 限制 slice/candidate/finding 数。

### 14.2 集成测试

- GitHub Actions 示例：
  - 类型为 `supply_chain_config`
  - 状态为 `static_only`
  - 不生成 native PoC

- C/C++ memcpy 示例：
  - 有 source/sink/guard
  - 类型为 `unsafe_memory_copy`
  - 静态验证为 `plausible`
  - 可进入 dynamic plan

- Exiv2 quick：
  - 5 分钟内完成
  - finding 分组清楚
  - debug 数据可信

- Exiv2 standard：
  - 8 到 12 分钟内完成
  - 动态验证最多 top3
  - blocked 原因清晰

### 14.3 回归测试

继续使用：

```text
python -m pytest tests/test_smoke.py -q
npm run build
```

不要使用裸 `python -m pytest -q` 作为基线，因为会收集 `runs/repos/...` 外部仓库测试。

## 15. 最终验收

下一轮整改完成后，系统应满足：

1. Exiv2 quick 模式可以快速反馈，不再 20 分钟起步。
2. 报告默认突出源码漏洞，配置风险不淹没主线。
3. Mining debug 能解释每一步数量变化。
4. LLM Director 的策略能被保存、展示、校验、执行。
5. Verification 明确分成静态验证、动态验证、Checker。
6. 非源码风险不再产生误导性的 PoC/blocked。
7. 源码 TopK finding 能真正尝试构建/运行/收集证据。
8. blocked 不再是笼统失败，而是精确缺口标签。

这轮改进完成后，系统才算从“agentic 扫描平台”迈向“agentic 漏洞挖掘与验证平台”。
