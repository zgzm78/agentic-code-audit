# Agentic Code Audit 下一阶段优化开发文档

## 1. 背景与当前结论

当前系统已经完成了任务编排、工具调度、项目画像、漏洞候选生成、验证闭环、报告与 UI 展示等工程主链路。系统可以完整跑通一次开源仓库审计任务，并能持久化 tool run、candidate、slice、finding、verification、artifact 与 report。

但从 Exiv2 实测结果看，当前漏洞挖掘能力仍偏弱。最新运行可以产出 finding，但主要集中在 GitHub Actions / Dependabot 供应链配置风险，没有挖掘到 Exiv2 核心 C/C++ 代码中的真实解析器漏洞、内存安全漏洞或可动态验证漏洞。

下一阶段的目标不是继续扩展 UI 或报告，而是提升核心漏洞挖掘质量，尤其是 C/C++ 项目的真实漏洞发现能力。

## 2. 当前主要问题

### 2.1 配置风险与源码漏洞混流

Semgrep 对 `.github/workflows`、`dependabot.yml` 的结果会进入 Mining 流程。这类 finding 本身有价值，但它们属于供应链配置风险，不应该与 C/C++ 源码漏洞混在同一个动态验证策略里。

已修复部分：

- 配置类 finding 不再因为缺少 `function_name` 被全部标记为 `invalid_candidate`。
- GitHub Actions / Dependabot 类结果可以进入 `supply_chain_config` 静态 finding。

仍需优化：

- LLM 返回的任意类型名需要被强制归一化。
- `supply_chain_config` 必须稳定 `should_verify=false`。
- 报告与 UI 需要明确区分“源码漏洞”和“配置风险”。

### 2.2 C/C++ 挖掘输入不足

当前可用工具中 Semgrep 信号最强，因此系统容易优先产出配置类或通用规则结果。对 Exiv2 这类 C/C++ 解析器项目，真正需要的输入包括：

- `cppcheck`
- `clang-tidy`
- `ctags`
- `clangd` 或 `libclang`
- sanitizer build 输出
- fuzz target / test binary / CLI entry 信息

如果这些工具不可用或没有被 Mining 正确消费，系统很难定位真实源码漏洞。

### 2.3 危险点规则过于浅层

当前危险点定位更擅长发现显式危险 API，例如：

- `strcpy`
- `sprintf`
- `memcpy`
- `system`
- `eval`
- SQL 拼接

但 C/C++ 解析器常见漏洞往往不是简单危险函数调用，而是：

- 长度字段信任
- offset/size 整数溢出
- 下标越界
- iterator 失效
- 类型转换截断
- signed/unsigned 混用
- buffer 边界检查缺失
- 递归解析深度失控
- 异常路径资源释放错误

这些需要更强的 source/sink/sanitizer 规则和数据流事实。

### 2.4 切片仍偏文本化

当前 `ProgramSlice` 已经结构化，但切片事实仍以局部上下文为主。它还不能稳定回答：

- 输入文件字节从哪里进入解析链路。
- size/offset/count 变量如何传播。
- guard 是否支配 sink。
- sanitizer 是否真的保护了危险操作。
- 跨函数参数是否保持约束。
- 错误处理路径是否提前返回。

因此候选质量不够稳定，LLM 容易根据表面证据生成弱 finding。

### 2.5 LLM 参与位置过重

LLM 适合做解释、摘要、候选归纳、报告语言优化，但不应该决定底层事实。当前候选类型、严重度、描述有时会被 LLM 输出污染，例如：

- `GitHub Actions Mutable Action Tag`
- `Supply Chain Compromise via Mutable Action Reference`
- `Insecure GitHub Action Pin`

这些应该统一归一为内部枚举，例如 `supply_chain_config`。

### 2.6 验证策略误选

配置类 finding 不应进入 C/C++ native verification。但当前部分 LLM 生成类型未被归一化，导致系统误判 `should_verify=true`，最终出现：

```text
blocked: Native PoC input generated, but no built CLI binary was found.
```

这会降低报告可信度，也浪费验证阶段资源。

## 3. 下一阶段总目标

下一阶段目标是把系统从“能跑通并产出通用扫描结果”提升到“能针对 C/C++ 项目挖掘真实源码漏洞线索”。

具体目标：

1. 分离源码漏洞、配置风险、依赖风险、secret 泄露四类 finding。
2. 强化 C/C++ 项目的危险点定位、切片和候选生成。
3. 让类型归一化、评分、验证策略由规则主导，LLM 只做辅助。
4. 让验证能力反向影响挖掘优先级，优先挖可构建、可运行、可触发的入口。
5. 增加可观测性：候选为什么 invalid、为什么被聚合、为什么进入或不进入验证，都要能在报告和调试数据中看到。

## 4. 优化阶段划分

## 阶段 A：Finding 类型归一化与风险分流

### A.1 新增内部标准类型

新增统一枚举或常量模块，例如 `vulnerability_types.py`：

```text
command_injection
sql_injection
path_traversal
unsafe_memory_copy
unsafe_c_string_api
integer_overflow
out_of_bounds_read
out_of_bounds_write
use_after_free
double_free
deserialization
code_execution
dependency_vulnerability
secret_leak
supply_chain_config
weak_static_proof
other
```

### A.2 增加类型归一化器

新增 `VulnerabilityTypeNormalizer`：

- 输入：LLM 类型、tool rule id、sink、file path、category。
- 输出：标准 `vulnerability_type`。
- 禁止最终 finding 使用任意 LLM 字符串作为类型。

示例规则：

```text
github-actions + mutable-action -> supply_chain_config
dependabot + cooldown -> supply_chain_config
gitleaks -> secret_leak
CVE/GHSA/OSV -> dependency_vulnerability
strcpy/sprintf/gets -> unsafe_c_string_api
memcpy/memmove + tainted size -> unsafe_memory_copy
offset + size arithmetic -> integer_overflow
operator[] / at / pointer arithmetic + tainted index -> out_of_bounds_read/write
```

### A.3 风险域分流

为 finding 增加或派生 `risk_domain`：

```text
source_code
dependency
secret
supply_chain_config
environment
```

策略：

- `source_code` 才进入动态验证。
- `dependency` 走版本和可达性证据。
- `secret` 走静态证据和轮换建议。
- `supply_chain_config` 走配置证据，不进入 native runtime verification。

### A.4 验收标准

- GitHub Actions mutable tag 统一输出 `supply_chain_config`。
- Dependabot cooldown 统一输出 `supply_chain_config`。
- 配置类 finding 永远 `should_verify=false`。
- 报告中配置类风险单独分组，不冒充源码漏洞。

## 阶段 B：C/C++ 工具链与工具结果消费增强

### B.1 工具可用性目标

优先支持：

- `cppcheck`
- `clang-tidy`
- `ctags`
- `rg`
- `semgrep`
- `cmake`
- `make`
- `ninja`
- `gcc/g++`
- `clang/clang++`
- `asan/ubsan`

可选支持：

- `clangd`
- `bear`
- `compiledb`
- `llvm-symbolizer`
- `valgrind`

### B.2 编译数据库识别

Recon 阶段识别：

- `compile_commands.json`
- `CMakePresets.json`
- `CMakeLists.txt`
- `Makefile`
- `meson.build`
- `configure`

Mining 阶段优先消费 `compile_commands.json`。如果没有，则尝试生成：

```text
cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

失败时记录环境缺口，而不是静默降级。

### B.3 cppcheck 结果解析

补齐 cppcheck finding 到内部 anchor 的映射：

- `arrayIndexOutOfBounds` -> `out_of_bounds_read/write`
- `bufferAccessOutOfBounds` -> `out_of_bounds_read/write`
- `integerOverflow` -> `integer_overflow`
- `memleak` -> `resource_leak`
- `nullPointer` -> `null_dereference`

### B.4 clang-tidy 结果解析

重点消费：

- `clang-analyzer-security.*`
- `clang-analyzer-core.*`
- `clang-analyzer-unix.*`
- `cppcoreguidelines-pro-bounds-*`
- `bugprone-*`

### B.5 验收标准

- Exiv2 运行时，C/C++ 源码文件进入候选池的数量高于 `.github` 配置文件。
- cppcheck/clang-tidy 缺失时报告明确显示缺口。
- cppcheck/clang-tidy 可用时，tool anchor 能追到 candidate 和 finding。

## 阶段 C：C/C++ 规则库增强

### C.1 新增规则目录

扩展当前 `rules/cpp`：

```text
rules/cpp/sources.yml
rules/cpp/sinks.yml
rules/cpp/sanitizers.yml
rules/cpp/guards.yml
rules/cpp/parser_patterns.yml
rules/cpp/cwe_mapping.yml
```

### C.2 Source 规则

重点识别：

- CLI 参数：`argv`
- 文件输入：`read`, `fread`, `ifstream::read`
- buffer 输入：`DataBuf`, `BasicIo`, `MemIo`, `FileIo`
- image/parser entry：`readMetadata`, `decode`, `parse`, `load`, `open`
- network/input stream：`recv`, `read`

### C.3 Sink 规则

重点识别：

- pointer arithmetic
- array indexing
- `memcpy`, `memmove`, `memcmp`
- `std::copy`
- `strcpy`, `strncpy`, `sprintf`, `snprintf`
- `new[]`, `resize`, `reserve`
- integer casts
- offset seeks
- parser loop reads

### C.4 Guard / Sanitizer 规则

识别：

- `if (size < ...)`
- `if (offset + len > size)`
- `throw`
- `return false`
- `assert`
- `std::min`
- `checkedAdd`
- `Safe::add`
- bounds helper

需要区分“存在 guard”和“guard 真的支配 sink”。第一版可先保守实现：

- 同函数内 sink 之前出现 guard，记为 weak guard。
- guard 中同时出现 source 变量和 sink size/index，记为 likely guard。
- guard 在 sink 之后，不计入保护。

### C.5 验收标准

- 对 C/C++ 示例能识别 source、sink、guard、missing_guard。
- 对 parser 风格代码能生成 `integer_overflow`、`out_of_bounds_read/write` 候选。
- 候选不再只依赖显式危险 API。

## 阶段 D：结构化切片增强

### D.1 函数边界

优先级：

1. `ctags`
2. `tree-sitter-cpp` 或 `libclang`
3. 当前 regex fallback

### D.2 函数内轻量数据流

实现 `CppLocalDataFlowAnalyzer`：

输入：

- function code
- source variable names
- sink line

输出：

- definitions
- aliases
- assignments
- size variables
- offset variables
- index variables
- guard expressions
- sink arguments

第一版只做函数内，不做全程序数据流。

### D.3 跨函数轻量调用链

基于 `ctags` 和文本搜索建立：

- function -> callees
- function -> callers
- sink function owner
- source entry owner

先支持 2 到 3 层调用链。

### D.4 ProgramSlice 字段质量要求

源码类 slice 必须尽量补齐：

```text
source
sink
sink_args
definitions
guards
missing_guards
sanitizers
call_chain
data_flow
code_excerpt
```

如果关键字段缺失，不直接丢弃，需保存 invalid 原因：

```text
missing_source
missing_sink
missing_function_boundary
missing_trigger_condition
weak_tool_evidence
```

### D.5 验收标准

- 每个 invalid candidate 能看到 invalid 原因。
- 每个 source_code finding 能展示 source-to-sink 切片。
- C/C++ 函数级 slice 不再只是前后 20 行文本。

## 阶段 E：候选生成与评分重构

### E.1 候选生成策略

候选来源分三类：

1. `tool_candidate`：来自 cppcheck/clang-tidy/semgrep 等工具。
2. `rule_candidate`：来自内部 source/sink/guard 规则。
3. `llm_candidate`：LLM 对结构化事实的解释，不能单独作为强证据。

### E.2 候选必填字段

源码类 candidate 必须包含：

```text
file_path
line_start
function_name
vulnerability_type
source
sink
sink_args
trigger_conditions
evidence_refs
```

配置类 candidate 必须包含：

```text
file_path
line_start
vulnerability_type
rule_id
configuration_key_or_line
evidence_refs
```

### E.3 评分公式调整

源码类 finding：

```text
sink_danger: 0-3
source_control: 0-3
reachability: 0-3
missing_guards: 0-2
tool_corroboration: 0-2
runtime_entry_bonus: 0-2
parser_context_bonus: 0-2
```

配置类 finding：

```text
rule_confidence: 0-3
asset_importance: 0-2
exploit_precondition: 0-2
tool_corroboration: 0-2
```

不同风险域使用不同评分公式，禁止配置类套用 source-to-sink 评分。

### E.4 聚合策略

源码类按：

```text
file + function + sink + source + vulnerability_type
```

配置类按：

```text
file + rule_id + line_start
```

依赖类按：

```text
package + version + advisory_id
```

### E.5 验收标准

- 同一 GitHub Actions mutable tag 不产生多种任意类型名。
- 配置类 finding 不触发 native verification。
- 源码类 finding 的 severity 与评分可解释。
- UI 可以展示 candidate invalid reason 和 score breakdown。

## 阶段 F：验证反向驱动 Mining

### F.1 Recon 输出可验证入口

Recon 需要稳定输出：

- CLI binary candidates
- test binaries
- fuzz targets
- library harness candidates
- parser entry files
- build feasibility
- sanitizer feasibility

### F.2 Mining 优先级调整

Mining 排序时优先：

1. 可被 CLI 或 test 触发的入口。
2. parser/read/decode/load 相关代码。
3. 有 source-to-sink 和 missing guard 的候选。
4. 有工具 corroboration 的候选。
5. 配置类和依赖类放到静态风险队列。

### F.3 Verification hint 反馈

如果验证阶段发现：

- 无 binary
- build 缺依赖
- harness 缺入口
- 输入格式不明确

则记录到任务画像中，下一次同仓库运行时用于调整 Mining 策略。

### F.4 验收标准

- Exiv2 这类 CLI/parser 项目，优先生成围绕 metadata parser 的候选。
- 没有 build 成功时，报告显示“源码候选存在，但动态验证缺环境”。
- 配置类 finding 不再出现“找不到 native binary”的 blocked 验证。

## 阶段 G：可观测性与调试能力

### G.1 Mining Debug Report

为每次任务生成 `mining-debug.json` artifact，包含：

```text
tool_anchor_count_by_tool
dangerous_function_count_by_kind
slice_count_by_language
candidate_validity_breakdown
invalid_candidate_reasons
aggregation_input_count
aggregation_output_count
finding_count_by_type
verification_queue_count
```

### G.2 UI 展示

任务详情增加：

- 候选总数
- valid / invalid 数量
- invalid reason Top N
- finding 类型分布
- source_code / config / dependency / secret 分布

### G.3 验收标准

- 出现 `候选 72，finding 0` 时，UI 能直接说明原因。
- 用户不用查 SQLite 就能知道候选在哪一步被过滤。
- 报告能解释“为什么没有源码漏洞 finding”。

## 5. 推荐实现顺序

### 第一批：低风险高收益

1. `VulnerabilityTypeNormalizer`
2. `risk_domain`
3. 配置类评分和验证策略分流
4. invalid candidate reason
5. `mining-debug.json`

这批能马上解决当前 Exiv2 结果不清晰的问题。

### 第二批：C/C++ 信号增强

1. cppcheck parser 增强
2. clang-tidy parser
3. ctags 函数边界和调用链增强
4. C/C++ source/sink/guard 规则库
5. CppLocalDataFlowAnalyzer 第一版

这批是提升真实源码漏洞发现能力的核心。

### 第三批：验证闭环增强

1. build feasibility 反馈到 Mining
2. sanitizer build 优先级
3. CLI/fuzz/test target 识别
4. C/C++ harness 生成
5. crash/ASAN/UBSAN evidence checker 增强

这批用于把源码候选推进到 verified / partially_verified。

## 6. 不建议下一阶段做的事情

暂不建议优先做：

- 大规模 UI 重写
- 复杂权限系统
- 多用户系统
- 云端任务队列
- 完整 CodeQL/Joern 深度集成
- AFL++ / libFuzzer 自动化大规模 fuzz
- 过早做论文级跨函数数据流

这些可以后置。当前瓶颈在 Mining 质量，不在展示层。

## 7. 测试计划

### 7.1 单元测试

- 类型归一化：
  - GitHub Actions mutable tag -> `supply_chain_config`
  - Dependabot cooldown -> `supply_chain_config`
  - gitleaks -> `secret_leak`
  - OSV/CVE -> `dependency_vulnerability`
  - cppcheck out-of-bounds -> `out_of_bounds_read/write`

- 候选有效性：
  - 配置类无 `function_name` 仍 valid。
  - 源码类无 `function_name` 为 invalid，并记录原因。
  - 源码类无 source/sink 为 invalid，并记录原因。

- 聚合：
  - 配置类按 `file + rule_id + line` 聚合。
  - 源码类按 `file + function + sink + source + type` 聚合。

- 验证策略：
  - `supply_chain_config` 不进入动态验证。
  - `dependency_vulnerability` 不默认进入动态验证。
  - `source_code` 且 score >= 阈值进入验证。

### 7.2 集成测试

- GitHub Actions 示例：
  - 产出 `supply_chain_config`
  - `should_verify=false`
  - 无 native verification blocked

- C/C++ 示例：
  - `memcpy` + tainted size + missing bounds -> `unsafe_memory_copy`
  - offset + size overflow -> `integer_overflow`
  - array index from input -> `out_of_bounds_read/write`

- Exiv2 回归：
  - 配置类风险单独分组。
  - C/C++ 源码候选数量可见。
  - 如果没有源码 finding，报告明确说明原因：工具缺失、切片不足、候选 invalid、评分不足或验证缺环境。

### 7.3 回归测试

继续保持：

```text
python -m pytest tests/test_smoke.py -q
npm run build
```

不要使用裸 `python -m pytest -q` 作为基线，因为会收集 `runs/repos/...` 外部仓库测试。

## 8. 验收标准

下一阶段完成后，系统应满足：

1. Finding 类型全部来自内部标准枚举。
2. 报告能区分源码漏洞、依赖风险、secret、供应链配置风险。
3. 配置类 finding 不进入 C/C++ 动态验证。
4. C/C++ 项目中源码候选不被 `.github` 配置结果淹没。
5. 每个候选都有 valid/invalid 状态和原因。
6. 每个 finding 都有 score breakdown 和 trace。
7. Exiv2 运行即使没有真实源码漏洞，也能解释没有挖到的原因。
8. 如果 C/C++ 工具链可用，系统能产生更接近真实漏洞的源码候选。

## 9. 目标状态

优化完成后的系统定位应从：

```text
工程闭环可跑通的通用审计平台
```

提升为：

```text
具备 C/C++ 真实源码漏洞线索发现能力的 agentic 审计平台
```

核心评价标准不是 finding 数量，而是：

- finding 是否来自真实源码风险。
- trace 是否能回到 source/sink/guard。
- 候选过滤是否可解释。
- 验证策略是否匹配风险类型。
- 报告是否能让人判断“这是漏洞、配置风险，还是弱线索”。
