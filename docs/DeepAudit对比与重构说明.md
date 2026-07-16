# DeepAudit 对比与重构说明

本轮重构把项目从轻量 CLI/Web Demo 推进到 DeepAudit 风格的全栈审计平台。框架保留当前项目已有代码，但把运行入口、任务状态、Agent 编排、漏洞挖掘和验证证据链做了系统化改造。

## 架构对比

| 维度 | DeepAudit | 当前实现 |
| --- | --- | --- |
| 前端 | React/Vite AgentAudit 页面 | React/Vite，SSE 实时任务界面 |
| 后端 | FastAPI + 任务 API | FastAPI + SQLite + 后台任务 |
| 队列 | worker/Redis 类结构 | 进程内后台任务，后续可替换 |
| 数据库 | 持久化任务、事件、finding | SQLite 表覆盖任务、事件、工具、切片、候选、验证和 artifact |
| Agent | Recon/Analysis/Verification/Tool | Recon/Tool/DangerousFunction/Slice/Candidate/Aggregator/Classifier/Verification/Report |
| 工具 | Semgrep、Bandit、Gitleaks、OSV 等 | Semgrep、Bandit、Gitleaks、OSV、npm audit、Trivy、内置规则 |
| 验证 | LLM harness + sandbox | LLM planner + Docker sandbox + EvidenceChecker |
| 报告 | 前端报告视图和导出 | Markdown/JSON、链路图、PoC、真实执行证据 |

## 运行流程

```text
Frontend 创建任务
  -> Backend 写入 SQLite task
  -> SSE 推送 Agent 事件
  -> Orchestrator 解析目标并执行工具
  -> 危险函数定位
  -> 切片分析
  -> 候选漏洞生成
  -> 线索汇聚
  -> 漏洞类型判定
  -> LLM 生成验证方案
  -> Docker sandbox 执行 harness/PoC
  -> EvidenceChecker 判定真实证据
  -> 存储 finding、verification、artifact
  -> 前端展示链路图和报告
```

## 漏洞挖掘变化

旧版本更像“工具结果合并器”。新版本按用户给出的源码分析架构拆成五个阶段：

1. 危险函数定位：定位 `strcpy/memcpy/system`、SQL/命令/路径遍历危险 API、secret、依赖漏洞等线索。
2. 切片分析：围绕危险点提取 source、sink、控制条件、参数约束、调用链上下文。
3. 候选漏洞生成：DeepSeek 必须输出函数、行号、危险点、触发条件，不能只给文件级描述。
4. 线索汇聚：合并工具结果、切片证据、LLM 判断和重复候选。
5. 漏洞类型判定：输出 CWE、严重性、可达性、可利用性、置信度和是否进入验证。

## 验证变化

验证阶段参考 DeepAudit 的动态验证方式，同时吸收 AnyPoC 的“分析、生成、检查”思想：

- `VerificationPlanner`: DeepSeek 自由设计 Python/Bash/JS harness、crafted input、编译命令或 CLI 回放方案。
- `BuildDecisionAgent`: 系统自动判断 C/C++ 是否需要构建，不把构建决策暴露成前端勾选项。
- `RuntimeManager`: 按 CLI、Service、Harness 三类运行形态调度真实执行。
- `SandboxExecutor`: 在 Docker sandbox 执行命令，保存脚本、命令、退出码、stdout、stderr、耗时和生成文件。
- `EvidenceChecker`: 不接受 LLM 自述为 verified，必须引用真实执行证据。

对 DeepAudit 源码的动态验证理解：

- DeepAudit 的 `VerificationAgent` 是 ReAct 形态，会调 `run_code`、`extract_function`、`sandbox_exec` 等工具。
- `run_code` 会把 LLM 生成的 Python/PHP/JS/Bash harness 放进 Docker 沙箱执行，沙箱默认网络隔离、限制内存和 CPU，并收集 stdout/stderr。
- 它更偏向 Fuzzing Harness，而不是完整端到端验证；适合 SQL 注入、命令注入、SSTI 这类函数级触发问题，但对需要启动真实服务或复杂宿主环境的漏洞覆盖不足。
- DeepAudit 的 `verification_method` 主要来自 LLM 最终 JSON，自身缺少独立 checker 交叉验证，因此可能出现“说跑过”但报告中看不到真实 stdout/stderr 证据的情况。
- 当前系统的改进点是 Oracle First：先生成 Verification Plan，再执行，再由 EvidenceChecker 只基于真实命令、退出码、stdout、stderr、HTTP 响应、ASAN/UBSAN 或 Canary 判定。

统一状态：

- `verified`
- `exploitable`
- `partially_verified`
- `not_reproducible`
- `blocked`
- `false_positive`
- `uncertain`

## Docker Compose

当前 compose：

- `frontend`: `http://127.0.0.1:3000`
- `backend`: `http://127.0.0.1:8000`
- `sandbox`: `agentic-code-audit-sandbox:local`

暂不引入 Postgres/Redis，原因是两周项目优先保证端到端闭环。SQLite 和进程内任务足够承载本地实验，后续可以平滑拆成 worker。

## 测试策略

已覆盖：

- DeepSeek key 缺失时任务拒绝启动。
- 危险函数定位和切片必须包含 source/sink/函数/行号。
- C/C++ finding 在缺少可运行二进制时生成 PoC artifact，并标记 `blocked`。
- EvidenceChecker 不允许空证据直接 verified。

后续建议补充：

- `examples/vulnerable-python` 端到端集成测试。
- Exiv2 C/C++ 系统自动构建决策和阻塞日志测试。
- 前端 SSE 渲染和 finding 详情页面测试。
