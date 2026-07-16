# Agentic Code Audit 下一阶段全面优化方案

## 1. 背景与当前结论

当前系统已完成任务编排、工具调度、项目画像、漏洞候选生成、验证闭环、报告与 UI 展示等工程主链路。系统可以完整跑通一次开源仓库审计任务，并能持久化 tool run、candidate、slice、finding、verification、artifact 与 report。

但从 Exiv2 实测结果看，当前漏洞挖掘能力仍偏弱。最新运行可以产出 finding，但主要集中在 GitHub Actions / Dependabot 供应链配置风险，没有挖掘到 Exiv2 核心 C/C++ 代码中的真实解析器漏洞、内存安全漏洞或可动态验证漏洞。

下一阶段的目标不是继续扩展 UI 或报告，而是提升核心漏洞挖掘质量，尤其是 C/C++ 项目的真实漏洞发现能力。

## 2. 架构评估与决策

### 2.1 DeepAudit ReAct vs 当前结构化流水线

经分析 DeepAudit 源码和数据库实际数据（Flask 2.0.0 审计案例），DeepAudit 的 ReAct 模式存在根本性缺陷：

| 维度 | DeepAudit ReAct | 当前结构化流水线 |
|------|----------------|-----------------|
| 覆盖率 | 不可控，LLM 决定何时停止 | 规则+工具穷举，保证危险 API 全覆盖 |
| 可解释性 | LLM 黑盒决策，无法追溯为什么跳过某个文件 | 每步输入输出可追溯，切片→候选→finding 全链路有 ID |
| 一致性 | 同一输入两次运行结果不同 | 确定性规则+工具，结果可复现 |
| 深度语义理解 | LLM 可理解复杂上下文 | 正则匹配无法理解语义 |
| 抗 LLM 幻觉 | `verification_method` 会说谎（Flask 案例中 0 条 poc_code 含实际执行痕迹） | EvidenceChecker 只认真实 stdout/stderr |

**结论：结构化流水线是更好的基础架构。** 安全审计的核心需求是"穷尽覆盖"和"可审计"，LLM ReAct 的"自主决定边界"与这两个目标根本冲突。

但结构化流水线有明显短板：**纯规则无法覆盖解析器漏洞的复杂语义模式**（如整数溢出、类型截断、iterator 失效）——这正是 Exiv2 挖不到源码漏洞的原因。

### 2.2 不需要 DeepAudit 式的总指挥 Agent

DeepAudit 的 Orchestrator 是 LLM 全权决策：决定看什么、看多深、什么时候停。Flask 2.0.0 案例中 9/14 个 HIGH findings 在验证前就被跳过——LLM 自己宣布完成但没有穷尽所有高危点。

**如果引入这种 Agent，会破坏当前架构"覆盖率确定性"的核心优势。**

### 2.3 需要 MiningDirector：战术层指挥官

不是取代流水线，而是在流水线内部做策略决策：

- "C/C++ 项目 + cppcheck 可用 + Exiv2 是图像解析器 → 优先关注 `readMetadata`/`parse`/`decode` 入口"
- "memcpy 出现 15 次，但只有 3 次有 tainted size → 对那 3 次启用 clang-tidy 针对性检查"
- "配置类候选占 80%，源码类只有 5 个 → 发出警告，在报告中解释原因"
- "上次验证 blocked 因为缺少 libexiv2-dev → 本次预处理检测依赖"

MiningDirector 的核心原则：

- **80% 规则引擎 + 20% LLM 辅助**：决策基于可审计事实（工具可用性、候选分布、项目类型），LLM 提供语义理解和策略建议
- **LLM 不能决定"停不停"**：流水线阶段顺序是固定的，LLM 只在阶段内部做战术选择
- **决策可解释**：每个策略决策都有理由记录，可追溯到触发条件

### 2.4 三层决策体系

```
┌──────────────────────────────────────────────────────────────┐
│  战略层（代码固定，不交给 LLM）                                │
│  · 流水线阶段顺序（Recon → Mining → Verification → Report）   │
│  · 风险域分流（源码/配置/依赖/Secret → 不同验证策略）          │
│  · 证据标准（Oracle 必须基于真实执行结果，禁止 LLM 自述）     │
│  · 输出格式（Finding 必须包含 source/sink/行号/函数名）       │
│  · 类型归一化（所有 vulnerability_type 强制归一为内部枚举）    │
├──────────────────────────────────────────────────────────────┤
│  战术层（LLM 决策 + 规则校验）  ← MiningDirector              │
│  · 工具组合选择（从可用工具清单中选择，不能编造）              │
│  · 候选优先级排序（哪些函数/路径值得优先深入）                 │
│  · 代码区域聚焦（识别解析器入口、CLI 入口、高风险模块）         │
│  · 自主代码探索（read_file + search_pattern + trace_variable）│
│  · 验证策略建议（根据项目类型建议 Oracle 类型）                │
├──────────────────────────────────────────────────────────────┤
│  执行层（工具/规则执行，不需要 LLM）                           │
│  · Semgrep / cppcheck / clang-tidy / CodeQL 等工具实际运行    │
│  · 规则引擎模式匹配（source/sink/guard/sanitizer）            │
│  · Docker sandbox 执行（harness/PoC）                         │
│  · EvidenceChecker 判定                                       │
│  · 报告生成                                                   │
└──────────────────────────────────────────────────────────────┘
```

**LLM 的自由度边界：**

| LLM 可以做 | LLM 不能做 |
|-----------|-----------|
| 从已安装工具清单中选择工具组合 | 跳过 Recon 直接开始 Mining |
| 对候选排序和分配优先级 | 宣布"没发现漏洞"而不跑完工具 |
| 主动发起对特定代码区域的深入阅读 | 自行变更 Finding 的 vulnerability_type |
| 建议聚焦的子系统和入口函数 | 自行判定 verified（EvidenceChecker 强制） |
| 根据历史验证反馈调整策略 | 决定"够了，不需要继续" |

## 3. 工具基础设施现状与修复

### 3.1 当前架构问题

系统有两个 Docker 容器，工具分布严重不均：

| 容器 | 用途 | C/C++ 工具链 | 总工具数 |
|------|------|-------------|---------|
| `backend` | Recon + Mining + 报告 | **全缺**（无 cppcheck, clang-tidy, ctags, cmake, gcc） | ~10 |
| `sandbox` | 验证执行 | **完整**（cppcheck, clang-tidy, cmake, gcc/g++, clang, valgrind, gdb, lldb, go, cargo, java, php） | 35+ |

**Mining 阶段运行在 backend 容器，但 C/C++ 工具全在 sandbox 容器。这是 Exiv2 挖不到 C/C++ 漏洞的基础设施层面根因——不是规则不够、不是切片太弱，是工具根本不可用。**

### 3.2 解决方案：Mining 工具通过 docker exec 路由到 Sandbox

Backend 已挂载 `/var/run/docker.sock` 且有 docker CLI，可直接在 sandbox 容器中执行 Mining 工具：

```python
# 当前：ToolRunner 在 backend 进程内 subprocess
result = self.tool_runner.run(invocation)  # backend 本地 → C/C++ 工具全部 skipped

# 修复后：C/C++ 工具通过 docker exec 在 sandbox 内执行
# Sandbox 容器名: agentic-code-audit-sandbox（docker-compose 已配置）
# docker exec agentic-code-audit-sandbox cppcheck --enable=all --xml ...
```

实现方式：在 `ToolRunner` 中增加 `executor` 策略：

```python
class ToolRunner:
    EXECUTORS = {
        "sandbox": ["cppcheck", "clang-tidy", "ctags", "cmake", "gcc", "g++",
                     "clang", "clang++", "valgrind", "gdb", "lldb",
                     "go", "gosec", "cargo", "cargo-audit",
                     "java", "mvn", "gradle", "php", "composer"],
        "local": ["rg", "semgrep", "gitleaks", "osv-scanner", "bandit",
                  "npm-audit", "pip-audit", "docker", "curl", "sqlite3",
                  "pytest", "node", "npm"],
    }
```

不需要修改 Dockerfile，不需要重新构建镜像。

### 3.3 Sandbox 完整工具清单

Mining 可用工具（通过 docker exec 路由后）：

**扫描类（11个）**

| 工具 | 用途 | 优先级 |
|------|------|--------|
| semgrep | 通用多语言静态分析 | 必选 |
| cppcheck | C/C++ 静态分析（内存、越界、溢出） | **核心** |
| clang-tidy | C/C++ 深度检查（clang-analyzer-*） | **核心** |
| bandit | Python 安全扫描 | 按语言 |
| gitleaks | 密钥泄露检测 | 必选 |
| osv-scanner | 依赖漏洞扫描 | 必选 |
| pip-audit | Python 依赖审计 | 按语言 |
| npm audit | Node.js 依赖审计 | 按语言 |
| composer audit | PHP 依赖审计 | 按语言 |
| cargo audit | Rust 依赖审计 | 按语言 |
| gosec | Go 安全扫描 | 按语言 |

**C/C++ 构建与分析（10个）**

| 工具 | 用途 |
|------|------|
| cmake | C/C++ 构建系统 + 生成 compile_commands.json |
| make | Makefile 构建 |
| ninja | Ninja 构建 |
| gcc / g++ | GNU 编译器 |
| clang / clang++ | LLVM 编译器（ASAN/UBSAN 支持更完善） |
| valgrind | 内存安全运行时分析 |
| gdb | GNU 调试器（crash 证据收集） |
| lldb | LLVM 调试器 |

**辅助工具（6个）**

| 工具 | 用途 |
|------|------|
| ripgrep | 快速代码搜索 |
| curl | HTTP 探测 |
| sqlite3 | SQLite 数据库检查 |
| pkg-config | 编译依赖检测 |
| file | 文件类型识别（二进制证据） |

**多语言运行时（7个）**

| 运行时 | 用途 |
|--------|------|
| python / pytest | Python harness 执行 |
| nodejs / npm | JavaScript harness 执行 |
| go | Go harness 执行 |
| cargo / rustc | Rust harness 执行 |
| java / mvn / gradle | Java harness 执行 |
| php / composer | PHP harness 执行 |

### 3.4 仍需单独安装的工具

以下工具在 Sandbox 中也不可用，需要按需安装：

| 工具 | 用途 | 优先级 | 安装方式 |
|------|------|--------|---------|
| ctags (universal-ctags) | C/C++ 函数边界提取、调用链 | **高** | `apt-get install universal-ctags`（加入 sandbox Dockerfile） |
| CodeQL CLI | 语义级代码查询 | 中 | 下载二进制到 `.tools/bin/` |
| trivy | 文件系统/容器漏洞 | 低 | 下载二进制到 `.tools/bin/` |
| joern | CPG 图分析 | 暂不装 | 复杂度高，短期收益不大 |
| bear / compiledb | compile_commands.json 生成 | 低 | cmake `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON` 可替代 |

**ctags 是最紧迫的缺失**，因为阶段 D 的切片增强依赖它获取函数边界和调用链。只需在 `docker/sandbox/Dockerfile` 的 apt-get 列表中加入 `universal-ctags` 即可。

### 3.5 当前问题清单（共 6 项）

#### 2.1 配置风险与源码漏洞混流

Semgrep 对 `.github/workflows`、`dependabot.yml` 的结果进入 Mining 流程后与 C/C++ 源码漏洞混在同一评分和验证策略里。

已修复部分：

- 配置类 finding 不再因为缺少 `function_name` 被全部标记为 `invalid_candidate`
- GitHub Actions / Dependabot 类结果可以进入 `supply_chain_config` 静态 finding

仍需优化：

- LLM 返回的任意类型名需要被强制归一化为内部标准枚举
- `supply_chain_config` 必须稳定 `should_verify=false`
- 报告与 UI 需要明确区分"源码漏洞"和"配置风险"

#### 2.2 C/C++ 挖掘输入不足 ← 【基础设施已定位】

当前可用工具中 Semgrep 信号最强，因此系统容易优先产出配置类或通用规则结果。对 Exiv2 这类 C/C++ 解析器项目，真正需要的 cppcheck、clang-tidy、ctags 等工具虽然在 Sandbox 中存在，但 Mining 阶段无法访问。

**根因已确认：Mining 在 backend 容器执行，C/C++ 工具全在 sandbox 容器。修复方案见 3.2。**

#### 2.3 危险点规则过于浅层

当前危险点定位更擅长发现显式危险 API（`strcpy`、`sprintf`、`memcpy`、`system`、`eval`、SQL 拼接），但 C/C++ 解析器常见漏洞往往不是简单危险函数调用，而是：

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

#### 2.4 切片仍偏文本化

当前 `ProgramSlice` 已经结构化，但切片事实仍以局部上下文为主。还不能稳定回答：

- 输入文件字节从哪里进入解析链路
- size/offset/count 变量如何传播
- guard 是否支配 sink
- sanitizer 是否真的保护了危险操作
- 跨函数参数是否保持约束
- 错误处理路径是否提前返回

因此候选质量不够稳定，LLM 容易根据表面证据生成弱 finding。

#### 2.5 LLM 参与位置过重

LLM 适合做解释、摘要、候选归纳、报告语言优化，但不应该决定底层事实。当前候选类型、严重度、描述有时会被 LLM 输出污染，例如：

- `GitHub Actions Mutable Action Tag`
- `Supply Chain Compromise via Mutable Action Reference`
- `Insecure GitHub Action Pin`

这些应该统一归一为 `supply_chain_config`。

#### 2.6 验证策略误选

配置类 finding 不应进入 C/C++ native verification。但当前部分 LLM 生成类型未被归一化，导致系统误判 `should_verify=true`，最终出现：

```text
blocked: Native PoC input generated, but no built CLI binary was found.
```

这会降低报告可信度，也浪费验证阶段资源。

## 4. 下一阶段总目标

把系统从"能跑通并产出通用扫描结果"提升到"能针对 C/C++ 项目挖掘真实源码漏洞线索"。

具体目标：

1. 分离源码漏洞、配置风险、依赖风险、secret 泄露四类 finding，各自走不同验证策略
2. 打通 Mining 到 Sandbox 的工具路由，让 C/C++ 工具信号真正进入流水线
3. 引入 MiningDirector 战术层，让 LLM 在规则约束下自主选择工具、排序候选、探索代码
4. 强化 C/C++ 项目的 source/sink/guard/sanitizer 规则库
5. 增强结构化切片，实现函数内轻量数据流
6. 让类型归一化、评分、验证策略由规则主导，LLM 只做辅助
7. 让验证能力反向影响挖掘优先级，优先挖可构建、可运行、可触发的入口
8. 增加可观测性：候选为什么 invalid、为什么被聚合、为什么进入或不进入验证，全部可见

## 5. 优化阶段划分

### 阶段 0：基础设施修复（新增，最高优先级）

**这是所有后续优化的前提——没有工具信号，再好的规则和切片也是空中楼阁。**

#### 0.1 ToolRunner 增加 docker exec 路由

```python
# 新增 SandboxExecutor 策略，对 EXECUTORS["sandbox"] 中的工具
# 通过 docker exec <sandbox_container> <command> 执行
# 保持与本地执行相同的 ToolResult 接口
```

#### 0.2 Sandbox Dockerfile 补充

```dockerfile
# 在 docker/sandbox/Dockerfile apt-get 列表中新增：
universal-ctags
```

#### 0.3 工具可用性检查增强

`ToolRegistry.check_tool()` 对 sandbox 工具类检查 `docker exec <sandbox> which <tool>` 而不是本地 `shutil.which()`。

#### 0.4 验收标准

- cppcheck 对 Exiv2 的 C/C++ 源码文件产生 findings（而非全部 skipped）
- clang-tidy 对 C/C++ 源码文件产生检查结果
- ctags 可提取 C/C++ 函数边界
- Mining 阶段的 tool_results 中 C/C++ 工具信号量超过 Semgrep

---

### 阶段 A：Finding 类型归一化与风险分流

#### A.1 新增内部标准类型

新增 `src/agentic_code_audit/vulnerability_types.py`：

```python
from enum import Enum

class VulnType(Enum):
    # 源码漏洞（进入动态验证）
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal"
    UNSAFE_MEMORY_COPY = "unsafe_memory_copy"
    UNSAFE_C_STRING_API = "unsafe_c_string_api"
    INTEGER_OVERFLOW = "integer_overflow"
    OUT_OF_BOUNDS_READ = "out_of_bounds_read"
    OUT_OF_BOUNDS_WRITE = "out_of_bounds_write"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    NULL_DEREFERENCE = "null_dereference"
    RESOURCE_LEAK = "resource_leak"
    DESERIALIZATION = "deserialization"
    CODE_EXECUTION = "code_execution"

    # 静态证据型（不进入动态验证）
    DEPENDENCY_VULNERABILITY = "dependency_vulnerability"
    SECRET_LEAK = "secret_leak"
    SUPPLY_CHAIN_CONFIG = "supply_chain_config"

    # 兜底
    WEAK_STATIC_PROOF = "weak_static_proof"
    OTHER = "other"


class RiskDomain(Enum):
    SOURCE_CODE = "source_code"           # → 动态验证
    DEPENDENCY = "dependency"             # → 版本/可达性证据
    SECRET = "secret"                     # → 静态证据 + 轮换建议
    SUPPLY_CHAIN_CONFIG = "supply_chain_config"  # → 配置证据，永不进入 native verification
    ENVIRONMENT = "environment"           # → 环境级风险
```

#### A.2 增加类型归一化器

新增 `VulnerabilityTypeNormalizer`：

- 输入：LLM 类型、tool rule id、sink、file path、category
- 输出：标准 `VulnType` 枚举
- 禁止最终 finding 使用任意 LLM 字符串作为类型

示例规则：

```text
github-actions + mutable-action → SUPPLY_CHAIN_CONFIG
dependabot + cooldown → SUPPLY_CHAIN_CONFIG
gitleaks → SECRET_LEAK
CVE/GHSA/OSV → DEPENDENCY_VULNERABILITY
strcpy/sprintf/gets → UNSAFE_C_STRING_API
memcpy/memmove + tainted size → UNSAFE_MEMORY_COPY
offset + size arithmetic → INTEGER_OVERFLOW
operator[]/at/pointer arithmetic + tainted index → OUT_OF_BOUNDS_READ/WRITE
cppcheck:arrayIndexOutOfBounds → OUT_OF_BOUNDS_READ/WRITE
cppcheck:bufferAccessOutOfBounds → OUT_OF_BOUNDS_READ/WRITE
cppcheck:integerOverflow → INTEGER_OVERFLOW
cppcheck:memleak → RESOURCE_LEAK
cppcheck:nullPointer → NULL_DEREFERENCE
clang-analyzer-security.* → 对应类型
cppcoreguidelines-pro-bounds-* → OUT_OF_BOUNDS_*
bugprone-* → 对应类型
```

#### A.3 风险域分流

为 finding 增加 `risk_domain` 字段：

- `source_code`：进入动态验证
- `dependency`：走版本和可达性证据
- `secret`：走静态证据和轮换建议
- `supply_chain_config`：走配置证据，`should_verify=false`，永不进入 native runtime verification
- `environment`：环境级风险

#### A.4 验收标准

- GitHub Actions mutable tag 统一输出 `supply_chain_config`
- Dependabot cooldown 统一输出 `supply_chain_config`
- cppcheck out-of-bounds 统一输出 `out_of_bounds_read/write`
- 配置类 finding 永远 `should_verify=false`
- 报告中配置类风险单独分组，不冒充源码漏洞

---

### 阶段 B：MiningDirector 战术指挥层（新增）

#### B.1 设计目标

MiningDirector 是战术层的指挥官，在流水线阶段内部做策略决策。它不是 ReAct Agent——它不决定"下一步做什么阶段"，而是在每个阶段内部决定"怎么做更好"。

#### B.2 核心接口

```python
@dataclass
class MiningStrategy:
    """MiningDirector 产出的战术决策"""
    # 工具层
    tool_selections: list[ToolSelection]     # 选哪些工具，各自优先级和参数
    tool_focus_directories: list[str]        # 每个工具的搜索范围
    skip_patterns: list[str]                 # 跳过的文件模式

    # 分析层
    priority_functions: list[str]            # 优先分析的函数名列表
    parser_entries: list[str]                # 识别出的解析器入口函数
    taint_sources: list[str]                 # 识别的污点来源变量名
    focus_subsystems: list[str]              # 重点关注的功能子系统

    # 代码探索指令（LLM 主动发起）
    code_exploration_tasks: list[CodeExplorationTask]

    # 验证层
    suggested_oracles: dict[str, str]        # 每种漏洞类型建议的 Oracle
    build_attempt: bool                      # 是否尝试 CMake 构建
    harness_candidates: list[str]            # 适合生成 harness 的函数

    # 元信息
    rationale: str                           # LLM 解释为什么这么选
    confidence: float                        # LLM 对自己策略的信心


class MiningDirector:
    """战术指挥官：LLM 决策 + 规则校验"""

    def formulate_strategy(
        self,
        profile: ProjectProfile,
        semantic_index: SemanticIndex,
        available_tools: list[ToolAvailability],
        historical_feedback: list[VerificationResult] | None,
        llm_client: DeepSeekClient,
    ) -> MiningStrategy:
        """
        1. 构建策略 prompt：仅暴露工具可用性清单和项目客观事实
        2. LLM 返回战术决策
        3. 规则引擎校验（见 B.3）
        4. 返回校验通过/修正后的策略
        """

    def autonomous_code_exploration(
        self,
        strategy: MiningStrategy,
        target: Path,
        llm_client: DeepSeekClient,
    ) -> list[CodeExplorationResult]:
        """
        执行 LLM 自主代码探索任务：
        - read_file(path, start, end)
        - search_pattern(pattern, directory)
        - trace_variable(var_name, function)

        LLM 在阶段内部主动阅读代码以：
        - 确认 source 是否真的是用户可控输入
        - 确认 guard 是否真正支配 sink
        - 查找 sanitizer 或替代保护措施
        - 判断触发条件在实际调用链中是否可达
        """

    def prioritize_candidates(
        self,
        candidates: list[VulnerabilityCandidate],
        strategy: MiningStrategy,
        llm_client: DeepSeekClient,
    ) -> list[VulnerabilityCandidate]:
        """按策略对候选排序，优先那些可构建/可运行/可触发的入口"""
```

#### B.3 规则引擎校验

MiningDirector 的 LLM 输出必须经过规则校验才能生效：

| 校验规则 | 违规处理 |
|---------|---------|
| 选的工具都在 `available_tools` 中 | 剔除不在清单中的工具 |
| `focus_directories` 在项目中真实存在 | 剔除不存在的路径 |
| 没有跳过必需的流水线步骤 | 拒绝策略，要求 LLM 重新生成 |
| 没有建议"不跑某个必需工具" | 自动补充必需工具 |

#### B.4 LLM 自主代码探索

给 LLM 提供三个只读能力，让它在 Mining 阶段内部主动探索代码：

```python
class CodeExplorationTools:
    """只读代码探索工具，LLM 可主动调用"""

    def read_file(self, path: str, start: int, end: int) -> str:
        """读取文件指定范围的行"""

    def search_pattern(self, pattern: str, directory: str) -> list[Match]:
        """在目录中正则搜索代码模式（基于 ripgrep）"""

    def trace_variable(self, var_name: str, function_name: str, file_path: str) -> TraceResult:
        """追踪变量在函数内的定义、赋值、使用点"""

    def find_callers(self, function_name: str) -> list[CallSite]:
        """查找函数的所有调用者（基于 ctags）"""

    def find_callees(self, function_name: str) -> list[CallSite]:
        """查找函数调用的所有子函数（基于 ctags）"""
```

**与 DeepAudit ReAct 的本质区别**：LLM 不能决定停不停、不能跳过阶段。它只是在阶段内部自主探索代码，产出更好的证据——最终仍然喂给规则的 CandidateGenerator 和 VulnerabilityClassifier。

#### B.5 Mining 优先级调整

Mining 排序时优先：

1. 可被 CLI 或 test 触发的入口代码
2. parser/read/decode/load 相关代码
3. 有 source-to-sink 和 missing guard 的候选
4. 有工具 corroboration 的候选（多个工具同时标记）
5. 配置类和依赖类放到静态风险队列，不参与源码评分排序

#### B.6 验收标准

- MiningDirector 对 Exiv2 能识别 `src/*image.cpp` 为主要解析器入口
- 工具选择策略的 rationale 字段可读可审计
- 所有 LLM 选择的工具都经过规则校验，不会出现选了未安装工具的情况
- 自主探索结果被记录到 mining-debug.json 中

---

### 阶段 C：C/C++ 工具链与工具结果消费增强

#### C.1 编译数据库识别

Recon 阶段识别：

- `compile_commands.json`
- `CMakePresets.json`
- `CMakeLists.txt`
- `Makefile`
- `meson.build`
- `configure`

Mining 阶段优先消费 `compile_commands.json`。如果没有，则尝试生成：

```bash
cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

失败时记录环境缺口，而不是静默降级。

#### C.2 cppcheck 结果解析增强

补齐 cppcheck finding 到内部类型的映射：

| cppcheck ID | VulnType |
|-------------|----------|
| arrayIndexOutOfBounds | OUT_OF_BOUNDS_READ / OUT_OF_BOUNDS_WRITE |
| bufferAccessOutOfBounds | OUT_OF_BOUNDS_READ / OUT_OF_BOUNDS_WRITE |
| integerOverflow | INTEGER_OVERFLOW |
| memleak | RESOURCE_LEAK |
| nullPointer | NULL_DEREFERENCE |
| uninitvar | 待分类 |
| uninitdata | 待分类 |
| doubleFree | DOUBLE_FREE |

#### C.3 clang-tidy 结果解析

重点消费以下 checker：

- `clang-analyzer-security.*`
- `clang-analyzer-core.*`
- `clang-analyzer-unix.*`
- `cppcoreguidelines-pro-bounds-*`
- `cppcoreguidelines-pro-type-*`
- `bugprone-*`
- `cert-*`

#### C.4 验收标准

- Exiv2 运行时，C/C++ 源码文件进入候选池的数量 > `.github` 配置文件数量
- cppcheck/clang-tidy 缺失时报告明确显示缺口和原因
- cppcheck/clang-tidy 可用时，tool anchor 能追踪到 candidate 和 finding
- cppcheck 的 `arrayIndexOutOfBounds` 映射为 `out_of_bounds_read/write`

---

### 阶段 D：C/C++ 规则库增强

#### D.1 规则目录结构

扩展当前 `rules/cpp`：

```text
rules/cpp/
├── dangerous_functions.yml   # 已有
├── sources.yml               # 已有，需大幅扩充
├── sanitizers.yml            # 已有
├── sinks.yml                 # 新增
├── guards.yml                # 新增
├── parser_patterns.yml       # 新增
└── cwe_mapping.yml           # 新增
```

#### D.2 Source 规则

重点识别：

- CLI 参数：`argv`, `argc`
- 文件输入：`read`, `fread`, `ifstream::read`, `FileIo::read`
- buffer 输入：`DataBuf`, `BasicIo`, `MemIo`, `FileIo`
- 图像/解析器入口：`readMetadata`, `decode`, `parse`, `load`, `open`, `readFile`
- 网络输入流：`recv`, `read`
- 环境变量：`getenv`

#### D.3 Sink 规则

重点识别：

- pointer arithmetic（指针算术运算）
- array indexing（数组下标访问 `operator[]`）
- `memcpy`, `memmove`, `memcmp`
- `std::copy`, `std::move`
- `strcpy`, `strncpy`, `sprintf`, `snprintf`
- `new[]`, `resize`, `reserve`
- integer casts（整数类型转换）
- offset seeks（文件偏移定位 `seekg`, `seekp`）
- parser loop reads（循环中累积读取）

#### D.4 Guard / Sanitizer 规则

识别保护措施：

- `if (size < ...)` / `if (offset + len > size)`
- `throw`, `return false`, `assert`
- `std::min`, `checkedAdd`, `Safe::add`
- bounds helper 函数

需要区分保护强度：

- 同函数内 sink 之前出现 guard → `weak_guard`
- guard 中同时出现 source 变量和 sink size/index → `likely_guard`
- guard 在 sink 之后 → 不计入保护
- guard 在错误处理路径中 → `error_path_guard`

#### D.5 验收标准

- 对 C/C++ 示例能识别 source、sink、guard、missing_guard
- 对 parser 风格代码能生成 `integer_overflow`、`out_of_bounds_read/write` 候选
- 候选不再只依赖显式危险 API（`strcpy`/`system`），也能捕获溢出和越界模式

---

### 阶段 E：结构化切片增强

#### E.1 函数边界提取优先级

1. `ctags`（universal-ctags，需在 Sandbox 中可用）
2. `tree-sitter-cpp` 或 `libclang`（可选增强）
3. 当前 regex fallback（保留作为兜底）

#### E.2 函数内轻量数据流

实现 `CppLocalDataFlowAnalyzer`：

输入：

- 函数代码（代码文本和函数边界）
- source 变量名列表
- sink 行号

输出：

- definitions（变量定义点）
- aliases（变量别名关系）
- assignments（赋值语句）
- size variables（与 sink 相关的 size 变量）
- offset variables（与 sink 相关的 offset 变量）
- index variables（数组索引变量）
- guard expressions（保护条件表达式）
- sink arguments（sink 调用的参数列表）

第一版只做函数内，不做跨函数全程序数据流。

#### E.3 跨函数轻量调用链

基于 `ctags` 和文本搜索建立：

- `function -> callees`（调用图向下）
- `function -> callers`（调用图向上）
- `sink function owner`（sink 所在函数）
- `source entry owner`（source 所在入口函数）

先支持 2 到 3 层调用链。

#### E.4 ProgramSlice 字段质量要求

源码类 slice 必须尽量补齐：

```text
source, sink, sink_args, definitions, guards,
missing_guards, sanitizers, call_chain, data_flow, code_excerpt
```

如果关键字段缺失，不直接丢弃，保存 invalid 原因：

```text
missing_source, missing_sink, missing_function_boundary,
missing_trigger_condition, weak_tool_evidence
```

#### E.5 验收标准

- 每个 invalid candidate 能看到具体 invalid 原因
- 每个 source_code finding 能展示 source-to-sink 切片
- C/C++ 函数级 slice 不再只是前后 20 行文本，而是基于 ctags 的精确函数边界
- 函数内能追踪 size/offset/index 变量的基本传播路径

---

### 阶段 F：候选生成与评分重构

#### F.1 候选来源分类

候选来源分三类，每类权重不同：

1. `tool_candidate`：来自 cppcheck/clang-tidy/semgrep/gitleaks 等工具（权重最高）
2. `rule_candidate`：来自内部 source/sink/guard 规则匹配
3. `llm_candidate`：LLM 对结构化事实的解释（权重最低，不能单独作为强证据）

#### F.2 候选必填字段

源码类 candidate 必须包含：

```text
file_path, line_start, function_name, vulnerability_type,
source, sink, sink_args, trigger_conditions, evidence_refs
```

配置类 candidate 必须包含：

```text
file_path, line_start, vulnerability_type, rule_id,
configuration_key_or_line, evidence_refs
```

#### F.3 评分公式——按风险域分离

**源码类 finding：**

```text
sink_danger:          0-3
source_control:       0-3
reachability:         0-3
missing_guards:       0-2
tool_corroboration:   0-2
runtime_entry_bonus:  0-2
parser_context_bonus: 0-2

total_max = 17
threshold_dynamic_verify = 8
```

**配置类 finding：**

```text
rule_confidence:      0-3
asset_importance:     0-2
exploit_precondition: 0-2
tool_corroboration:   0-2

total_max = 9
should_verify = false（硬编码）
```

#### F.4 聚合策略

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

#### F.5 验收标准

- 同一 GitHub Actions mutable tag 不产生多种任意类型名
- 配置类 finding 不触发 native verification
- 源码类 finding 的 severity 与评分可解释
- UI 可以展示 candidate invalid reason 和 score breakdown

---

### 阶段 G：验证反向驱动 Mining

#### G.1 Recon 输出可验证入口

Recon 需要稳定输出：

- CLI binary candidates
- test binaries
- fuzz targets
- library harness candidates
- parser entry files
- build feasibility
- sanitizer feasibility

这些信息进入 `ProjectProfile`，供 MiningDirector 消费。

#### G.2 验证结果反馈

如果验证阶段发现：

- 无 binary
- build 缺依赖
- harness 缺入口
- 输入格式不明确

则记录到验证反馈中，存入任务级别的 feedback store。MiningDirector 下一次同仓库运行时读取反馈，调整策略：

```python
# 伪代码
if historical_feedback:
    for feedback in historical_feedback:
        if feedback.status == "blocked" and feedback.reason == "no_binary":
            strategy.build_attempt = True
            strategy.rationale += " 上次验证因缺少 binary 而阻塞，本次优先尝试构建。"
        if feedback.status == "blocked" and feedback.reason == "missing_entry":
            strategy.priority_functions.append(feedback.entry_point)
```

#### G.3 验收标准

- Exiv2 这类 CLI/parser 项目，优先生成围绕 metadata parser（`readMetadata`/`decode`/`parse`）的候选
- 没有 build 成功时，报告显示"源码候选存在，但动态验证缺环境"，而非"无漏洞"
- 配置类 finding 不再出现"找不到 native binary"的 blocked 验证

---

### 阶段 H：可观测性与调试能力

#### H.1 Mining Debug Report

为每次任务生成 `mining-debug.json` artifact，包含：

```json
{
  "tool_anchor_count_by_tool": {"semgrep": 45, "cppcheck": 67, "clang-tidy": 23},
  "dangerous_function_count_by_kind": {"dangerous_api": 82, "tool_finding": 93, "dependency_vulnerability": 15},
  "slice_count_by_language": {"C++": 120, "Python": 30, "YAML": 18},
  "candidate_validity_breakdown": {"valid": 47, "invalid": 25},
  "invalid_candidate_reasons": {"missing_function_boundary": 10, "missing_source": 8, "missing_sink": 7},
  "aggregation_input_count": 47,
  "aggregation_output_count": 32,
  "finding_count_by_type": {"supply_chain_config": 5, "unsafe_memory_copy": 8, "integer_overflow": 3},
  "finding_count_by_risk_domain": {"source_code": 15, "supply_chain_config": 5, "dependency": 8, "secret": 4},
  "mining_director_strategy": { "...": "..." },
  "code_exploration_results": [],
  "tool_execution_breakdown": {"local": 8, "sandbox_docker_exec": 12, "skipped": 3},
  "verification_queue_count": 15
}
```

#### H.2 UI 展示

任务详情增加：

- 候选总数 / valid / invalid 数量
- invalid reason Top N
- finding 类型分布
- source_code / config / dependency / secret 分布
- score breakdown（每个 finding）
- MiningDirector 策略说明

#### H.3 验收标准

- 出现"候选 72，finding 0"时，UI 能直接说明过滤原因
- 用户不用查 SQLite 就能知道候选在哪一步被过滤
- 报告能解释"为什么没有源码漏洞 finding"（工具缺失/切片不足/候选 invalid/评分不足/验证缺环境）

---

## 6. 推荐实现顺序

### 第一批（本周）：止血 + 基础设施

1. **阶段 0**：ToolRunner docker exec 路由 → sandbox（改动 ~100 行）
2. **阶段 0**：Sandbox Dockerfile 加 `universal-ctags`（1 行改动）
3. **阶段 A**：`VulnerabilityTypeNormalizer` + `RiskDomain` + `VulnType` 枚举（新增 ~300 行）
4. **阶段 H**（部分）：`mining-debug.json` 基础版本（新增 ~80 行）

**这批能立即生效**：Exiv2 跑出 C/C++ 工具信号 + 类型不再乱 + 可看到候选过滤原因。

### 第二批（下周）：C/C++ 信号增强 + 战术层

5. **阶段 B**：MiningDirector 第一版（工具选择 + 候选排序，新增 ~400 行）
6. **阶段 C**：cppcheck/clang-tidy parser 增强（改动 ~200 行）
7. **阶段 D**：C/C++ source/sink/guard 规则库（新增 rules 文件 ~500 行 YAML）
8. **阶段 D**（部分）：CppLocalDataFlowAnalyzer 第一版（新增 ~300 行）

**这批是核心提升**：Exiv2 的 parser 代码能产出 `integer_overflow`、`out_of_bounds_*` 候选。

### 第三批（后续）：评分 + 验证闭环

9. **阶段 E**：ctags 函数边界 + 调用链增强（改动 ~250 行）
10. **阶段 F**：评分重构（改动 ~200 行）
11. **阶段 G**：验证反向反馈（新增 ~200 行）
12. **阶段 H**：UI 增强展示 candidate/finding 分布

---

## 7. 不建议下一阶段做的事情

- 大规模 UI 重写
- 复杂权限系统 / 多用户系统
- 云端任务队列（Redis/Postgres）
- 完整 CodeQL/Joern 深度集成
- AFL++ / libFuzzer 自动化大规模 fuzz
- 过早做论文级跨过程数据流分析
- 多语言（Go/Rust/Java/PHP）动态验证完善

这些可以后置。当前瓶颈在 Mining 质量，不在展示层或基础设施层。

---

## 8. 测试计划

### 8.1 基础设施测试

- Sandbox docker exec 工具路由：
  - `docker exec agentic-code-audit-sandbox cppcheck --version` 正常返回
  - `docker exec agentic-code-audit-sandbox clang-tidy --version` 正常返回
  - `docker exec agentic-code-audit-sandbox ctags --version` 正常返回
  - Sandbox 不可用时 tool result 记录为 `blocked` 而非 `skipped`

### 8.2 单元测试

- 类型归一化：
  - GitHub Actions mutable tag → `supply_chain_config`
  - Dependabot cooldown → `supply_chain_config`
  - gitleaks → `secret_leak`
  - OSV/CVE → `dependency_vulnerability`
  - cppcheck out-of-bounds → `out_of_bounds_read/write`
  - cppcheck integerOverflow → `integer_overflow`

- 候选有效性：
  - 配置类无 `function_name` 仍 valid
  - 源码类无 `function_name` 为 invalid，并记录原因 `missing_function_boundary`
  - 源码类无 source/sink 为 invalid，并记录原因

- 聚合：
  - 配置类按 `file + rule_id + line` 聚合
  - 源码类按 `file + function + sink + source + type` 聚合

- 验证策略：
  - `supply_chain_config` `should_verify=false`
  - `dependency_vulnerability` `should_verify=false`
  - `source_code` 且 `score >= threshold` `should_verify=true`

- MiningDirector：
  - LLM 选的工具都在 `available_tools` 中
  - 选了不在清单中的工具被规则引擎剔除
  - rationale 字段非空

### 8.3 集成测试

- GitHub Actions 示例：
  - 产出 `supply_chain_config`
  - `should_verify=false`
  - 无 "blocked: no native binary" 验证结果

- C/C++ 示例：
  - `memcpy` + tainted size + missing bounds → `unsafe_memory_copy`
  - offset + size overflow → `integer_overflow`
  - array index from input → `out_of_bounds_read/write`

- Exiv2 回归：
  - 配置类风险单独分组
  - C/C++ 源码候选数量 > 配置类候选数量（工具路由修复后）
  - cppcheck/clang-tidy 结果可见于 tool_results
  - 如果没有源码 finding，报告明确说明原因：工具缺失/切片不足/候选 invalid/评分不足/验证缺环境

### 8.4 回归测试

继续保持：

```bash
python -m pytest tests/test_smoke.py -q
cd frontend && npm run build
```

不要使用裸 `python -m pytest -q` 作为基线，因为会收集 `runs/repos/...` 外部仓库测试。

---

## 9. 验收标准

下一阶段完成后，系统应满足：

1. **工具基础设施**：Mining 阶段能通过 docker exec 使用 Sandbox 中的所有 C/C++ 工具
2. **类型归一化**：所有 Finding 类型来自内部标准枚举，不存在 LLM 任意字符串
3. **风险域分流**：报告能区分源码漏洞、依赖风险、secret、供应链配置风险
4. **验证策略正确**：配置类 finding 不进入 C/C++ 动态验证，不出现 "no native binary" blocked
5. **C/C++ 信号充足**：C/C++ 项目中源码候选不被 `.github` 配置结果淹没
6. **候选可解释**：每个候选都有 valid/invalid 状态和原因
7. **评分可解释**：每个 finding 都有 score breakdown 和 trace
8. **Exiv2 归因清晰**：Exiv2 运行即使没有真实源码漏洞，也能解释没有挖到的原因
9. **LLM 边界清晰**：LLM 在战术层做决策但不能跳过阶段、编造类型、自行判定 verified
10. **可观测性**：mining-debug.json 记录全链路过滤和决策信息

---

## 10. 目标状态

优化完成后的系统定位应从：

```text
工程闭环可跑通的通用审计平台
```

提升为：

```text
具备 C/C++ 真实源码漏洞线索发现能力的 agentic 审计平台，
LLM 在明确边界内自主决策工具策略和代码探索方向
```

核心评价标准不是 finding 数量，而是：

- finding 是否来自真实源码风险（而非配置/依赖）
- trace 是否能回到 source/sink/guard
- 候选过滤是否可解释
- 验证策略是否匹配风险类型
- LLM 的战术决策是否在规则约束内且可审计
- 报告是否能让人判断"这是漏洞、配置风险，还是弱线索"
