# Agentic Code Audit 完整开发实施文档

本文档面向 AI 开发执行，要求实现完整系统，不按 MVP 或演示版处理。开发时应优先保证架构正确、证据闭环、可扩展工具模块、真实动态验证和可追溯报告。

## 0. 开发原则

1. 大模型必选，当前默认供应商为 DeepSeek，默认模型为 `deepseek-v4-pro`；系统设计上要保留 provider/model 可替换能力。
2. Agent 必须使用工具和证据，不允许全靠 LLM 分析源码。
3. ToolModule 是共享能力层，不是 Agent。
4. 漏洞挖掘五步流程属于 `VulnerabilityMiningAgent` 内部实现。
5. 动态验证必须在 Docker 沙箱中执行，并保存真实证据。
6. 报告必须中文输出，且能追溯每个 finding 的代码位置、触发链、PoC 和执行证据。
7. 所有长任务必须有进度事件、心跳、取消检查和 artifact。

## 1. 阶段一：核心数据模型和状态机

### 1.1 目标

先把完整系统的数据契约确定下来，避免后续 Agent 各写各的结构。

### 1.2 需要实现的数据结构

`Task`:

- `id`
- `target`
- `target_type`: `github | local | archive`
- `commit`
- `status`: `queued | running | completed | failed | cancelled`
- `model`
- `current_agent`
- `current_phase`
- `progress_done`
- `progress_total`
- `started_at`
- `finished_at`

`AgentEvent`:

- `task_id`
- `sequence`
- `agent`
- `phase`
- `event_type`: `thought | tool_start | tool_end | llm_start | llm_end | finding | verification | report | heartbeat | error`
- `message`
- `metadata`
- `created_at`

`ToolRun`:

- `tool`
- `command`
- `status`
- `exit_code`
- `duration_ms`
- `stdout_artifact_id`
- `stderr_artifact_id`
- `parsed_artifact_id`
- `summary`
- `cache_key`
- `cache_hit`

`DangerousFunction`:

- `file`
- `line`
- `function`
- `language`
- `symbol`
- `kind`
- `source_or_sink`
- `tool`
- `rule_id`
- `evidence`
- `confidence`

`ProgramSlice`:

- `dangerous_function_id`
- `file`
- `function`
- `line`
- `source`
- `sink`
- `call_chain`
- `data_flow`
- `guards`
- `sanitizers`
- `code_excerpt`
- `tool_evidence_ids`

`CandidateVulnerability`:

- `slice_id`
- `title`
- `vuln_type`
- `cwe`
- `file`
- `function`
- `line`
- `sink`
- `trigger_condition`
- `impact`
- `assumptions`
- `missing_checks`
- `evidence_ids`
- `validity`: `valid | invalid_candidate`

`Finding`:

- `candidate_id`
- `title`
- `vuln_type`
- `cwe`
- `severity`
- `confidence`
- `reachability`
- `exploitability`
- `evidence_strength`
- `verification_status`
- `chain_graph`
- `should_verify`
- `verification_reason`

`VerificationAttempt`:

- `finding_id`
- `strategy`
- `plan`
- `commands`
- `scripts_artifact_ids`
- `exit_code`
- `stdout_artifact_id`
- `stderr_artifact_id`
- `generated_files`
- `duration_ms`
- `checker_verdict`
- `checker_reason`

### 1.3 完成标准

- 后端 API 能返回完整任务、事件、finding、验证、artifact。
- 所有状态变化写入事件流。
- 任意 finding 可以追溯到 candidate、slice、dangerous function、tool run、artifact。

## 2. 阶段二：ToolModule

### 2.1 目标

把工具调用从固定 pipeline 步骤中拆出来，做成所有 Agent 可调用的工具服务。

### 2.2 实现内容

实现 `ToolRegistry`:

- 注册工具名称、用途、语言适配、安装检查命令、默认超时、并发限制。
- 提供 `list_available_tools(project_profile)`。
- 提供 `recommend_tools(agent, phase, project_profile)`。

实现 `ToolRunner`:

- 支持本机执行和 Docker 沙箱执行。
- 捕获 command、cwd、env、exit code、stdout、stderr、duration。
- 输出保存到 artifact，不只保存在日志。
- 支持 timeout。
- 支持取消检查。

实现 `ToolCache`:

- 对扫描类工具缓存结果。
- cache key 包含 commit、工具版本、参数、文件 hash。
- 前端事件中标记 cache hit。

实现 `ToolParsers`:

- Semgrep JSON parser。
- Gitleaks JSON parser。
- OSV JSON parser。
- Bandit JSON parser。
- cppcheck XML/文本 parser。
- CodeQL SARIF parser。
- 通用 stdout/stderr parser。

### 2.3 工具安装策略

项目目录下保留 `tools/` 或 `.tools/` 作为可选本地工具目录；Docker 镜像中安装稳定工具；找不到工具时记录 `tool_unavailable`，不能静默跳过。

阶段二必须完成核心工具安装闭环，而不是只写 registry：

- 更新 `scripts/install_tools.ps1`，安装/检查 `rg`、`semgrep`、`gitleaks`、`osv-scanner`、`bandit`、`trivy`；`npm audit` 依赖 Node/npm，脚本中只做版本检查。
- 更新 `docker/sandbox/Dockerfile`，安装/检查 `ripgrep`、`semgrep`、`gitleaks`、`osv-scanner`、`bandit`、`trivy`、Node/npm。
- 更新 `ToolRegistry`，将上述工具标为阶段二核心工具，其中 `rg`、`semgrep`、`gitleaks`、`osv-scanner`、`trivy` 为 required，语言专项工具按项目语言推荐。
- 更新 `ToolParsers`，确保 Semgrep/Gitleaks/OSV/Bandit/npm audit/trivy 输出可结构化解析。
- 增加测试：核心工具可用性检测、工具缺失状态、parser、cache、artifact 保存。

阶段二不安装 `CodeQL`、`Joern`、`AFL++`、`libFuzzer` 这类重型工具，只在 registry 中保留 optional 检测项。

### 2.4 完成标准

- Recon、Mining、Verification 都通过 ToolModule 调工具。
- 没有单独 `SecurityToolRunner` 线性阶段。
- 工具结果有结构化 parsed 输出和原始 artifact。

## 3. 阶段三：ReconAgent

### 3.1 目标

自动理解项目，不要求用户手工选择语言、构建方式、运行方式或验证入口。Recon 的结果要能支撑后续 LLM 自动制定验证方案。

### 3.2 实现方法

并行执行：

- Git 信息：remote、commit、branch、submodule。
- 文件树：语言比例、目录结构、测试目录、示例目录。
- 构建入口：CMakeLists、Makefile、configure、meson、package.json、pyproject、requirements、go.mod、Cargo.toml、pom.xml、build.gradle、composer.json、Gemfile、Dockerfile、docker-compose、CI 配置。
- 运行入口：CLI main、server entry、library export、framework plugin、examples、tests、scripts、container entrypoint。
- 环境入口：运行时版本、系统依赖、数据库、消息队列、外部服务、环境变量、配置文件。
- 依赖清单：lockfile、manifest、SBOM。
- 历史漏洞：OSV/依赖扫描结果。

LLM 使用方式：

- 输入工具摘要和少量关键文件。
- 输出项目画像：主要语言、核心模块、攻击面、推荐挖掘重点、可运行入口、可验证入口、不可运行风险、建议的弱化验证策略。
- 不允许 LLM 编造构建方式，必须引用检测到的文件或工具结果。

### 3.3 完成标准

- 对 Exiv2 能识别为 C++ 项目，识别 CMake/配置文件/CLI 目标。
- 对 Python/JS 示例项目能识别测试入口和 Web/CLI 入口。
- 前端能看到项目画像和后续计划。

### 3.4 阶段三工具补充

阶段三以项目画像为主，不强制安装重型分析工具，但必须为下一阶段漏洞挖掘准备静态工具接入点：

- `ToolRegistry` 增加/确认 `cppcheck`、`clang-tidy`、`pip-audit`、`gosec`、`cargo-audit`、`trivy`、`CodeQL`、`Joern` 的 optional 状态和能力标签。
- `scripts/install_tools.ps1` 可以先安装轻量工具：`cppcheck`、`pip-audit`、`cargo-audit`；`clang-tidy` 依赖 LLVM，可先做检测和安装说明。
- `docker/sandbox/Dockerfile` 可安装轻量工具和运行时依赖，但 `CodeQL`、`Joern` 仍建议 optional。
- Recon 的 `recommended_tools` 必须根据语言输出这些工具是否建议使用，以及当前是否 available。

## 4. 阶段四：VulnerabilityMiningAgent

### 4.1 总体流程

`VulnerabilityMiningAgent` 内部必须实现：

1. 危险函数定位。
2. 切片分析。
3. 候选漏洞生成。
4. 线索汇聚。
5. 漏洞类型判定。

每个子步骤都要发事件、保存中间结果、可被报告引用。

### 4.2 危险函数定位实现

#### 4.2.1 规则库

建立 `rules/` 目录：

- `rules/cpp/dangerous_functions.yml`
- `rules/cpp/sources.yml`
- `rules/cpp/sanitizers.yml`
- `rules/python/dangerous_apis.yml`
- `rules/javascript/dangerous_apis.yml`
- `rules/common/cwe_mapping.yml`

C/C++ 初始 sink：

- 内存复制：`strcpy`, `strncpy`, `strcat`, `sprintf`, `vsprintf`, `memcpy`, `memmove`, `gets`, `scanf`
- 命令执行：`system`, `popen`, `exec*`
- 文件路径：`fopen`, `open`, `ifstream`, path join/normalize
- 解析入口：图片、压缩包、网络协议、二进制格式解析函数

C/C++ 初始 source：

- `argv`
- 文件读取 buffer
- 网络读取
- 图像/metadata 字段
- 环境变量
- 外部配置

Python 初始 sink：

- `subprocess.*` with `shell=True`
- `os.system`
- SQL 字符串拼接
- `pickle.loads`
- path 拼接后读取

JavaScript 初始 sink：

- `child_process.exec`
- `eval`
- `new Function`
- SQL 拼接
- path traversal

#### 4.2.2 工具组合

每个语言至少运行：

- `rg` 规则检索。
- Semgrep 规则。
- AST 函数边界提取。

C/C++ 额外尝试：

- ctags。
- cppcheck。
- clang-tidy。
- CodeQL 或 Joern，若可用。

阶段四引入的工具必须同步完成安装/检测闭环：

- 更新 `scripts/install_tools.ps1`：补 `cppcheck`、`pip-audit`、`cargo-audit`、`gosec`、`trivy` 的安装或清晰安装提示；`clang-tidy` 优先检测 LLVM 安装状态。
- 更新 `docker/sandbox/Dockerfile`：补 `cppcheck`、`clang-tidy`、`pip-audit`、`trivy`、Go/Rust 基础工具中可稳定安装的部分。
- 更新 `ToolParsers`：cppcheck XML/文本、pip-audit JSON、cargo-audit JSON、gosec JSON、trivy JSON。
- 缺失 optional 工具时不能阻塞挖掘，但 finding/candidate 要记录该工具未运行的原因。

#### 4.2.3 排序

危险点排序使用：

- sink 危险程度。
- 是否有用户可控 source。
- 是否在解析入口/CLI/网络入口路径上。
- 是否已有工具规则命中。
- 是否缺少明显 guard。

### 4.3 切片分析实现

#### 4.3.1 输入

输入为危险点列表和项目画像。

#### 4.3.2 函数内切片

基于 AST：

- 找到 sink 调用所在函数。
- 提取 sink 参数变量。
- 向上回溯变量定义、赋值、函数返回值。
- 收集影响 sink 参数的条件判断。
- 收集长度、边界、空指针、类型、权限检查。

输出示例：

```json
{
  "sink": "memcpy(dst, src, len)",
  "sink_args": ["dst", "src", "len"],
  "definitions": ["len = header.size", "src = input.data"],
  "guards": ["if (len > 0)", "if (!src) return"],
  "missing_guards": ["len <= dst_size 未证明"],
  "source": "header.size from input file"
}
```

#### 4.3.3 跨函数切片

优先级：

1. 使用 CodeQL/Joern 查询调用链和数据流。
2. 使用 clangd/libclang 或 ctags 构建轻量调用图。
3. 退化为文本级调用者搜索。

跨函数切片必须限制深度，默认：

- caller depth: 3
- callee depth: 2
- max files per slice: 8
- max tokens per LLM prompt: 按模型上下文预算裁剪

#### 4.3.4 LLM 切片解释

对每个高风险切片批量调用当前配置的大模型，要求输出：

- source 是否用户可控。
- sink 参数是否受 source 影响。
- guard 是否足够。
- 触发条件。
- 不确定点。

LLM 输入必须包含工具生成的切片 JSON 和关键代码片段，不能让模型全仓库自由分析。

### 4.4 候选漏洞生成实现

#### 4.4.1 Prompt 约束

要求当前配置的大模型只输出 JSON，字段固定：

- `title`
- `vuln_type`
- `cwe`
- `file`
- `function`
- `line`
- `sink`
- `source`
- `trigger_condition`
- `missing_check`
- `impact`
- `confidence`
- `assumptions`
- `verification_ideas`

#### 4.4.2 Schema 校验

如果缺少 `file/function/line/sink/trigger_condition`，标记为 `invalid_candidate`。

#### 4.4.3 批处理

不要一个切片一个请求串行等待。应按语言和漏洞类型分组，批量请求，每批 3 到 8 个切片，根据 token 预算动态调整。

### 4.5 线索汇聚实现

实现 `ClueAggregator`：

- 用 canonical key 合并重复候选。
- 合并 tool evidence。
- 合并多个 source/sink 路径。
- 计算 evidence strength。
- 生成优先级。

Evidence strength 规则：

- `strong`: 至少一个静态工具命中 + 完整 source-sink 切片 + LLM 判断一致。
- `medium`: source/sink 明确，但跨函数链或 guard 判断不完整。
- `weak`: 只有危险 API 或 LLM 假设，缺少完整触发链。

### 4.6 漏洞类型判定实现

实现 `VulnerabilityClassifier`：

- 映射 CWE。
- 计算 severity。
- 判断 reachability。
- 判断 exploitability。
- 决定是否进入验证。
- 生成链路图初稿。

严重性计算不要只靠 LLM，建议用加权规则：

- sink 危险性 0-3。
- source 可控性 0-3。
- 可达性 0-3。
- 影响 0-3。
- guard 缺失 0-2。
- 验证结果加权。

## 5. 阶段五：VerificationAgent 与 ExploitAgent

### 5.1 验证总体方法

每个进入验证的 finding 走以下流程：

1. 读取 finding、slice、tool evidence、项目画像。
2. LLM 生成验证计划。
3. RuntimeManager 选择执行方式。
4. BuildManager 自动构建或准备 harness。
5. SandboxExecutor 执行命令。
6. EvidenceCollector 保存所有证据。
7. EvidenceChecker 独立判定。
8. ExploitAgent 生成 PoC、触发链和复现说明。
9. 失败时根据原因重试或标记 blocked/not_reproducible。

### 5.2 RuntimeManager

RuntimeManager 的职责不是只判断“能不能构建”，而是根据 finding、项目画像和环境画像选择最合适的验证路径。运行时类型至少包括：

- `cpp_cli`: 编译项目 CLI 后用 crafted input 触发。
- `cpp_harness`: 生成最小 C/C++ harness 调用目标函数。
- `python_test`: 生成 pytest 或直接运行脚本。
- `node_test`: 生成 npm/vitest/jest 脚本。
- `go_test`: 生成 Go test 或最小 Go harness。
- `rust_test`: 生成 cargo test 或最小 Rust harness。
- `java_test`: 生成 JUnit/Maven/Gradle 测试或最小 main。
- `php_test`: 生成 PHPUnit/CLI 脚本。
- `http_service`: 启动服务并发送 HTTP 请求。
- `library_harness`: 对库项目生成最小调用程序。
- `plugin_mock_host`: 对插件/框架扩展生成 mock 宿主环境。
- `container_runtime`: 使用项目 Dockerfile/docker-compose 启动目标。
- `dependency_only`: 依赖漏洞无法源码触发时生成受影响版本证据和利用条件。
- `weak_static_proof`: 项目无法执行时，用静态可达性、局部切片和依赖证据进行弱化验证。
- `static_blocked`: 入口、依赖、环境或权限缺失，保留静态证据和阻塞原因。

选择策略：

- 有 CLI 入口优先 CLI 回放。
- 有导出函数但无 CLI 时生成语言对应 harness。
- 有测试框架时优先新增测试。
- Web 项目优先本地服务请求。
- 有 Dockerfile/docker-compose 时优先复用项目容器，但仍要限制网络和资源。
- 库、SDK、插件、框架扩展项目优先生成 mock 宿主或最小调用者。
- 如果项目不能独立运行，进入弱化验证，不允许直接放弃。
- C/C++ 内存漏洞优先 sanitizer 构建。

### 5.3 EnvironmentManager 与 BuildManager

`EnvironmentManager` 负责多语言环境准备，`BuildManager` 只是其中一个子模块。开发时不要把验证架构写成只服务 C/C++。

基础 Docker 沙箱镜像应尽量预装常用运行时和工具：

- Python、pip、uv、poetry、pytest、tox。
- Node.js、npm、pnpm、yarn、vitest、jest。
- Go、Rust/cargo、Java/Maven/Gradle。
- PHP/composer、Ruby/bundler。
- gcc/g++、clang/clang++、cmake、ninja、make、meson、pkg-config。
- curl、httpie/httpx、sqlite3、常见数据库 client。
- Semgrep、Gitleaks、OSV、Bandit、cppcheck 等基础安全工具。

阶段五必须补齐动态验证和利用所需运行环境工具：

- 更新 `docker/sandbox/Dockerfile`：安装 `cmake`、`ninja`、`make`、`gcc/g++`、`clang/clang++`、ASAN/UBSAN/LSAN 支持、`valgrind`、`gdb/lldb`、`curl`、`sqlite3`、常见数据库 client、Python/Node/Go/Rust/Java/PHP 基础运行时。
- 更新 `scripts/install_tools.ps1`：Windows 本机至少检测上述工具；能稳定安装的工具可自动安装，复杂工具给出明确安装提示和版本检测。
- 更新 `ToolRegistry`：将运行环境工具纳入 `environment` / `verification` capability，不再只登记漏洞扫描工具。
- 更新 `EnvironmentManager`：根据 Recon 输出选择需要的运行时、构建工具、mock 工具和数据库 client。
- 更新 `SandboxExecutor`：执行前记录工具版本，缺失时返回 `blocked` 并保存缺失工具列表和安装建议。

环境准备流程：

1. 根据 Recon 结果选择 runtime profile。
2. 检查沙箱中运行时和包管理器版本。
3. 根据 lockfile/manifest 安装依赖，默认使用缓存目录。
4. 如果依赖安装需要外网，记录需要网络的原因；本地课程环境可允许配置开关，但默认验证执行阶段仍应无外网。
5. 为数据库、HTTP 服务、消息队列、文件系统、环境变量准备 mock 或 sentinel。
6. 保存环境准备命令、日志和失败原因。

BuildManager 自动化：

1. 检测构建系统。
2. 根据语言生成构建、测试或运行命令。
3. 对支持 sanitizer 的语言生成 sanitizer/调试构建命令。
4. 设置并行度和超时。
5. 捕获依赖缺失。
6. 记录构建 artifact。

C/C++ sanitizer flags：

```bash
-fsanitize=address,undefined -fno-omit-frame-pointer -g
```

如果环境准备、依赖安装或构建失败，仍然尝试：

- 语言级最小 harness。
- 只运行相关测试或只编译相关源文件。
- mock 外部依赖、数据库、HTTP 服务、消息队列或宿主框架。
- 使用项目 examples/fixtures 构造触发输入。
- 退化为静态可达性证明 + 局部执行 + blocked 证据。

弱化验证状态要求：

- `partially_verified`: source-sink 可达、局部 harness 可执行，但完整产品环境未复现。
- `blocked`: 缺失关键运行时、系统依赖、私有服务、授权数据或宿主环境，且已有失败日志。
- `uncertain`: 静态证据不足，无法证明也无法否定。

### 5.4 VerificationPlanner

Prompt 必须要求模型输出 JSON，并让模型显式说明语言、运行环境和降级策略：

- `strategy`
- `rationale`
- `setup_commands`
- `files_to_create`
- `commands`
- `expected_signal`
- `oracle`
- `fallbacks`
- `environment_requirements`
- `mock_strategy`
- `weak_verification_strategy`
- `safety_notes`

示例 oracle：

- ASAN 输出包含 `heap-buffer-overflow`。
- stderr 包含 sanitizer 报告和目标函数栈。
- exit code 非 0 且不是构建失败。
- HTTP 响应证明路径穿越读到 sandbox 内 sentinel 文件。
- SQL 注入返回了不应返回的数据。
- 命令注入创建了 sandbox sentinel 文件。
- 单元测试断言证明越权、绕过或异常状态。
- mock 服务收到不应出现的请求或参数。

### 5.5 SandboxExecutor

Docker 沙箱约束：

- 默认无外网。
- 限制 CPU、内存、运行时间。
- 挂载临时 workspace。
- 只允许访问当前任务 artifact 目录。
- 执行前记录文件树 hash，执行后记录变化。

### 5.6 EvidenceChecker

Checker 应规则化实现，不依赖 LLM 自述：

- `MemorySafetyChecker`: 解析 ASAN/UBSAN/Valgrind。
- `CommandInjectionChecker`: 检查 sentinel 文件、stdout/stderr、exit code。
- `PathTraversalChecker`: 检查是否读到 sandbox sentinel。
- `SQLInjectionChecker`: 检查返回结果是否突破预期条件。
- `CrashChecker`: 检查 crash、signal、core、stack trace。
- `GenericChecker`: 对无法规则判断的情况，给 `uncertain`，不标 verified。

LLM 可以辅助解释证据，但最终状态必须由 checker 依据真实证据给出。



## 6. 阶段六：报告与 UI

### 6.1 报告内容

报告必须包含：

- 任务信息：目标、commit、模型、时间、工具版本。
- 项目画像。
- 工具扫描摘要。
- Finding 总览。
- 每个 finding 的详细信息：
  - 漏洞位置。
  - 漏洞类型/CWE/等级/置信度。
  - source-sink 链路。
  - 代码片段。
  - Mermaid 触发链路图。
  - 验证方案。
  - PoC。
  - 执行命令。
  - stdout/stderr 摘要。
  - checker 判定。
  - 修复建议。
- blocked/not_reproducible 的原因。

### 6.2 前端要求

前端应展示：

- 历史任务列表，点击只查看，不自动运行。
- 创建任务后必须点击“开始审计”才运行。
- 停止按钮。
- 顶部进度栏。
- Agent 树：顶层 Agent + Mining 内部子步骤。
- 工具调用流。
- LLM 调用流。
- Finding 列表分类：
  - `verified`
  - `exploitable`
  - `partially_verified`
  - `blocked`
  - `not_reproducible`
  - `false_positive`
  - `uncertain`
- 链路图，节点类型：
  - `source`
  - `function`
  - `condition`
  - `sanitizer`
  - `sink`
  - `effect`
  - `artifact`
- artifact 下载。

UI 文案中报告页标题用“报告”，不要写“中文报告”。

## 7. 阶段七：并发、缓存和性能

### 7.1 并发策略

实现任务内并发：

- Recon 子任务并发。
- 工具扫描并发。
- 切片并发。
- LLM 批处理并发。
- 验证并发。

建议配置：

```env
MAX_TOOL_CONCURRENCY=4
MAX_LLM_CONCURRENCY=2
MAX_SLICE_WORKERS=4
MAX_SANDBOX_CONCURRENCY=2
TOOL_TIMEOUT_SECONDS=300
BUILD_TIMEOUT_SECONDS=900
VERIFY_TIMEOUT_SECONDS=300
```

### 7.2 进度估算

每个阶段设置 `progress_total`：

- Recon: 子任务数量。
- DangerousFunctionLocator: 工具数量 + 规则组数量。
- SliceAnalyzer: 危险点数量。
- CandidateGenerator: LLM batch 数量。
- ClueAggregator: 候选数量。
- Classifier: 聚合 finding 数量。
- Verification: finding 数量 * 尝试次数。
- Report: 报告章节数量。

### 7.3 超时与取消

每个循环、工具执行、LLM 调用、构建、验证前后都检查取消状态。取消后：

- 停止派发新任务。
- 尝试终止运行中的 subprocess/container。
- 标记 task `cancelled`。
- 保留已完成 artifact。

## 8. 阶段八：测试与评估

### 8.1 单元测试

必须覆盖：

- 大模型 API key 缺失拒绝启动。
- ToolModule 执行、超时、artifact 保存。
- Semgrep/Gitleaks/OSV parser。
- 危险函数定位规则。
- AST 函数边界提取。
- 切片 source/sink/guard 提取。
- candidate schema 校验。
- EvidenceChecker 不接受空证据 verified。
- 取消状态检查。

### 8.2 集成测试

示例项目：

- `examples/vulnerable-python`: SQL 注入、命令注入、路径穿越。
- `examples/vulnerable-js`: child_process、path traversal、template injection。
- `examples/vulnerable-cpp`: strcpy/memcpy 越界、整数溢出、路径问题。
- Exiv2：至少跑到 C/C++ 危险函数定位、切片、候选、环境/构建尝试、验证计划和 blocked/partially_verified 证据。
- 至少一个 Python、Node.js、Go/Rust/Java 中的非 C/C++ 示例能完成动态验证。
- 至少一个不可独立运行的库/插件示例能走 mock harness 或 weak_static_proof，并给出清楚降级证据。

### 8.3 Docker Compose 测试

必须验证：

- 一键启动。
- 前端可访问。
- `/api/health` 正常。
- 创建任务不自动开始。
- 点击开始后 SSE 有事件。
- 点击停止后任务取消。
- 报告可下载。
- artifact 可下载。

### 8.4 质量门槛

合并前必须通过：

- Python 单元测试。
- 前端 build。
- Docker compose config。
- 至少一个端到端示例项目。
- 至少一个动态验证成功 finding。
- 至少一个 blocked finding 有清楚阻塞证据。

## 9. AI 开发执行顺序建议

建议按以下顺序让 AI 开发，避免先写 UI 或轻量 pipeline：

1. 先实现数据模型和状态机。
2. 再实现 ToolModule，并替换掉独立工具扫描阶段。
3. 实现 ReconAgent 自动画像。
4. 实现 VulnerabilityMiningAgent 五步内部流程。
5. 实现 VerificationAgent 的 sandbox 执行和 EvidenceChecker。
6. 实现 ExploitAgent 的 PoC 生成和回放。
7. 实现报告生成。
8. 最后优化前端展示、并发和缓存。

每个阶段都要有测试和 artifact，不允许只写接口空壳。

## 10. Definition of Done

完整系统完成时应满足：

- 可以输入 GitHub 仓库 URL 或本地路径。
- 大模型必选且参与所有关键分析阶段；当前默认 DeepSeek `deepseek-v4-pro`，但 provider/model 可替换。
- Agent 使用工具结果做判断，不靠纯 LLM。
- ToolModule 可被多个 Agent 调用并缓存结果。
- 漏洞挖掘遵循危险函数定位、切片分析、候选生成、线索汇聚、类型判定。
- 动态验证在 Docker 沙箱执行。
- finding 有 verification status。
- verified/exploitable finding 有真实执行证据。
- blocked finding 有清楚阻塞原因、环境准备日志、构建/执行日志或弱化验证说明。
- 报告为中文，包含漏洞链路、PoC、证据和修复建议。
- 前端能显示历史任务、手动开始、停止、实时进度、工具调用、链路图和报告。
