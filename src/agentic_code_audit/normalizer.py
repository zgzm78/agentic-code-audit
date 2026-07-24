"""VulnerabilityTypeNormalizer — LLM/tool type strings -> standard VulnType.

The normalizer is the single source of truth for type classification.
All candidate/finding types MUST pass through it; raw LLM strings are
never used as the final vulnerability_type.
"""

from __future__ import annotations

import re
from typing import Any

from .vulnerability_types import VulnType


# ---------------------------------------------------------------------------
# Tool rule-id -> VulnType mappings (exact match)
# ---------------------------------------------------------------------------
CPPCHECK_TYPE_MAP: dict[str, VulnType] = {
    "arrayIndexOutOfBounds": VulnType.OUT_OF_BOUNDS_READ,
    "arrayIndexOutOfBoundsCond": VulnType.OUT_OF_BOUNDS_READ,
    "bufferAccessOutOfBounds": VulnType.OUT_OF_BOUNDS_WRITE,
    "integerOverflow": VulnType.INTEGER_OVERFLOW,
    "integerOverflowCond": VulnType.INTEGER_OVERFLOW,
    "memleak": VulnType.RESOURCE_LEAK,
    "memleakOnRealloc": VulnType.RESOURCE_LEAK,
    "nullPointer": VulnType.NULL_DEREFERENCE,
    "nullPointerDefaultArg": VulnType.NULL_DEREFERENCE,
    "nullPointerRedundantCheck": VulnType.NULL_DEREFERENCE,
    "uninitvar": VulnType.OTHER,
    "uninitdata": VulnType.OTHER,
    "doubleFree": VulnType.DOUBLE_FREE,
    "uninitMemberVar": VulnType.OTHER,
    "unusedFunction": VulnType.OTHER,
    "unknownEvaluationOrder": VulnType.OTHER,
    "assertWithSideEffect": VulnType.OTHER,
    "stlOutOfBounds": VulnType.OUT_OF_BOUNDS_READ,
    "ctuOneDefinitionRuleViolation": VulnType.OTHER,
    "exceptThrowInDestructor": VulnType.OTHER,
    "exceptRethrowCopy": VulnType.OTHER,
    "invalidContainer": VulnType.OTHER,
    "invalidFunctionArg": VulnType.OTHER,
    "invalidPointer": VulnType.NULL_DEREFERENCE,
    "invalidScanfArgType": VulnType.OTHER,
    "invalidLifetime": VulnType.OTHER,
    "knownConditionTrueFalse": VulnType.OTHER,
    "missingReturn": VulnType.OTHER,
    "noConstructor": VulnType.OTHER,
    "noCopyConstructor": VulnType.OTHER,
    "noOperatorEq": VulnType.OTHER,
    "noDestructor": VulnType.OTHER,
    "postfixOperator": VulnType.OTHER,
    "returnDanglingLifetime": VulnType.OTHER,
    "returnReference": VulnType.OTHER,
    "returnTempReference": VulnType.OTHER,
    "selfAssignment": VulnType.OTHER,
    "syntaxError": VulnType.OTHER,
    "unusedVariable": VulnType.OTHER,
    "unusedStructMember": VulnType.OTHER,
    "unsignedLessThanZero": VulnType.OTHER,
    "unreachableCode": VulnType.OTHER,
    "useAutoPointerContainer": VulnType.OTHER,
    "wrongPrintfScanfArgNum": VulnType.OTHER,
    "zerodiv": VulnType.OTHER,
    "zerodivcond": VulnType.OTHER,
}

CLANG_TIDY_TYPE_MAP: dict[str, VulnType] = {
    "clang-analyzer-security.insecureAPI.strcpy": VulnType.UNSAFE_C_STRING_API,
    "clang-analyzer-security.insecureAPI.bcopy": VulnType.UNSAFE_MEMORY_COPY,
    "clang-analyzer-security.insecureAPI.bcmp": VulnType.OTHER,
    "clang-analyzer-security.insecureAPI.memset": VulnType.OTHER,
    "clang-analyzer-security.insecureAPI.memcpy": VulnType.UNSAFE_MEMORY_COPY,
    "clang-analyzer-security.insecureAPI.memmove": VulnType.UNSAFE_MEMORY_COPY,
    "clang-analyzer-security.insecureAPI.strcat": VulnType.UNSAFE_C_STRING_API,
    "clang-analyzer-security.insecureAPI.strncat": VulnType.UNSAFE_C_STRING_API,
    "clang-analyzer-security.insecureAPI.strncpy": VulnType.UNSAFE_C_STRING_API,
    "clang-analyzer-security.insecureAPI.sprintf": VulnType.UNSAFE_C_STRING_API,
    "clang-analyzer-security.insecureAPI.vsprintf": VulnType.UNSAFE_C_STRING_API,
    "clang-analyzer-security.insecureAPI.gets": VulnType.UNSAFE_C_STRING_API,
    "clang-analyzer-security.insecureAPI.rand": VulnType.OTHER,
    "clang-analyzer-security.insecureAPI.mktemp": VulnType.OTHER,
    "clang-analyzer-security.insecureAPI.mkstemp": VulnType.OTHER,
    "clang-analyzer-security.insecureAPI.UncheckedReturn": VulnType.OTHER,
    "clang-analyzer-security.FloatLoopCounter": VulnType.OTHER,
    "clang-analyzer-core.NullDereference": VulnType.NULL_DEREFERENCE,
    "clang-analyzer-core.DivideZero": VulnType.OTHER,
    "clang-analyzer-core.uninitialized.Assign": VulnType.NULL_DEREFERENCE,
    "clang-analyzer-core.uninitialized.Branch": VulnType.NULL_DEREFERENCE,
    "clang-analyzer-core.uninitialized.UndefReturn": VulnType.OTHER,
    "clang-analyzer-core.CallAndMessage": VulnType.OTHER,
    "clang-analyzer-core.StackAddressEscape": VulnType.OTHER,
    "clang-analyzer-core.DynamicTypePropagation": VulnType.OTHER,
    "clang-analyzer-unix.Malloc": VulnType.RESOURCE_LEAK,
    "clang-analyzer-unix.MallocSizeof": VulnType.OTHER,
    "clang-analyzer-unix.API": VulnType.OTHER,
    "clang-analyzer-unix.cstring.BadSizeArg": VulnType.OTHER,
    "clang-analyzer-unix.cstring.NullArg": VulnType.OTHER,
    "clang-analyzer-cplusplus.NewDeleteLeaks": VulnType.RESOURCE_LEAK,
    "clang-analyzer-cplusplus.NewDelete": VulnType.OTHER,
    "clang-analyzer-cplusplus.InnerPointer": VulnType.OTHER,
    "cppcoreguidelines-pro-bounds-array-to-pointer-decay": VulnType.OUT_OF_BOUNDS_READ,
    "cppcoreguidelines-pro-bounds-constant-array-index": VulnType.OUT_OF_BOUNDS_READ,
    "cppcoreguidelines-pro-bounds-pointer-arithmetic": VulnType.OUT_OF_BOUNDS_WRITE,
    "cppcoreguidelines-pro-type-const-cast": VulnType.OTHER,
    "cppcoreguidelines-pro-type-cstyle-cast": VulnType.OTHER,
    "cppcoreguidelines-pro-type-reinterpret-cast": VulnType.OTHER,
    "cppcoreguidelines-pro-type-static-cast-downcast": VulnType.OTHER,
    "cppcoreguidelines-pro-type-union-access": VulnType.OTHER,
    "cppcoreguidelines-pro-type-vararg": VulnType.OTHER,
    "bugprone-branch-clone": VulnType.OTHER,
    "bugprone-integer-division": VulnType.OTHER,
    "bugprone-misplaced-widening-cast": VulnType.INTEGER_OVERFLOW,
    "bugprone-signed-char-misuse": VulnType.OTHER,
    "bugprone-sizeof-expression": VulnType.OTHER,
    "bugprone-undefined-memory-manipulation": VulnType.OTHER,
    "bugprone-suspicious-memset-usage": VulnType.OTHER,
    "bugprone-suspicious-memory-comparison": VulnType.OTHER,
    "bugprone-suspicious-semicolon": VulnType.OTHER,
    "bugprone-unused-return-value": VulnType.OTHER,
    "bugprone-use-after-move": VulnType.USE_AFTER_FREE,
    "bugprone-narrowing-conversions": VulnType.INTEGER_OVERFLOW,
    "bugprone-implicit-widening-of-multiplication-result": VulnType.INTEGER_OVERFLOW,
    "bugprone-incorrect-roundings": VulnType.OTHER,
    "cert-env33-c": VulnType.OTHER,
    "cert-err34-c": VulnType.OTHER,
    "cert-msc30-c": VulnType.OTHER,
    "cert-msc50-cpp": VulnType.OTHER,
    "cert-str34-c": VulnType.OTHER,
}

# ---------------------------------------------------------------------------
# LLM-generated type string -> VulnType (fuzzy matching via keywords)
# ---------------------------------------------------------------------------
LLM_TYPE_KEYWORDS: list[tuple[list[str], VulnType]] = [
    # Supply chain / config (must be checked first — highest priority)
    (
        [
            "github action", "github-action", "github_actions", "githubactions",
            "mutable action", "mutable-action", "mutable_ref", "mutable ref",
            "dependabot", "cooldown", "workflow",
            "supply chain", "supply-chain", "supply_chain",
            "action pin", "action-pin", "pinned action", "unpinned",
            "cis benchmark", "hardening",
        ],
        VulnType.SUPPLY_CHAIN_CONFIG,
    ),
    # Secret leak
    (
        ["gitleaks", "secret", "credential", "password", "api key", "api_key", "token leak", "hardcoded"],
        VulnType.SECRET_LEAK,
    ),
    # Dependency
    (
        ["cve", "ghsa", "osv", "pysec", "rustsec", "gosect", "dependency", "vulnerable package", "outdated"],
        VulnType.DEPENDENCY_VULNERABILITY,
    ),
    # Command injection
    (
        ["command injection", "command-injection", "os command", "shell injection", "shell metacharacter"],
        VulnType.COMMAND_INJECTION,
    ),
    # SQL injection
    (
        ["sql injection", "sql-injection", "sqli", "blind sql", "union select"],
        VulnType.SQL_INJECTION,
    ),
    # Path traversal
    (
        ["path traversal", "path-traversal", "directory traversal", "lfi", "file inclusion"],
        VulnType.PATH_TRAVERSAL,
    ),
    # Memory safety
    (
        ["buffer overflow", "buffer-overflow", "buffer overrun", "stack overflow", "stack-based"],
        VulnType.OUT_OF_BOUNDS_WRITE,
    ),
    (
        ["out of bounds read", "out-of-bounds read", "oob read", "buffer over-read", "buffer overread"],
        VulnType.OUT_OF_BOUNDS_READ,
    ),
    (
        ["out of bounds write", "out-of-bounds write", "oob write", "heap overflow", "heap-based"],
        VulnType.OUT_OF_BOUNDS_WRITE,
    ),
    (
        ["out of bounds", "out-of-bounds", "oob access", "bounds check", "array index"],
        VulnType.OUT_OF_BOUNDS_READ,
    ),
    (
        ["integer overflow", "integer-overflow", "int overflow", "signed overflow", "unsigned overflow", "wraparound"],
        VulnType.INTEGER_OVERFLOW,
    ),
    (
        ["use after free", "use-after-free", "uaf", "dangling pointer", "dangling reference"],
        VulnType.USE_AFTER_FREE,
    ),
    (
        ["double free", "double-free"],
        VulnType.DOUBLE_FREE,
    ),
    (
        ["null pointer", "null-pointer", "null dereference", "null-dereference", "nil dereference"],
        VulnType.NULL_DEREFERENCE,
    ),
    (
        ["memory leak", "memory-leak", "memleak", "resource leak", "resource-leak", "fd leak"],
        VulnType.RESOURCE_LEAK,
    ),
    (
        ["unsafe c string", "unsafe-c-string", "unsafe strcpy", "unsafe strcat", "unsafe sprintf",
         "unsafe gets", "strcpy", "strcat", "sprintf", "gets("],
        VulnType.UNSAFE_C_STRING_API,
    ),
    (
        ["unsafe memory copy", "unsafe-memory-copy", "unsafe memcpy", "unsafe memmove", "memcpy without bounds"],
        VulnType.UNSAFE_MEMORY_COPY,
    ),
    # Deserialization
    (
        ["deserialization", "deserialisation", "untrusted deserialization", "pickle", "marshal", "yaml load"],
        VulnType.DESERIALIZATION,
    ),
    # Code execution
    (
        ["code execution", "code-execution", "rce", "remote code execution", "eval injection", "arbitrary code"],
        VulnType.CODE_EXECUTION,
    ),
]

# ---------------------------------------------------------------------------
# Sink-pattern -> VulnType (regex-based, used as fallback)
# ---------------------------------------------------------------------------
SINK_PATTERN_MAP: list[tuple[str, VulnType]] = [
    (r"\bstrcpy\b", VulnType.UNSAFE_C_STRING_API),
    (r"\bstrcat\b", VulnType.UNSAFE_C_STRING_API),
    (r"\bsprintf\b", VulnType.UNSAFE_C_STRING_API),
    (r"\bsscanf\b", VulnType.UNSAFE_C_STRING_API),
    (r"\bscanf\b", VulnType.UNSAFE_C_STRING_API),
    (r"\bgets\b", VulnType.UNSAFE_C_STRING_API),
    (r"\bmemcpy\b", VulnType.UNSAFE_MEMORY_COPY),
    (r"\bmemmove\b", VulnType.UNSAFE_MEMORY_COPY),
    (r"\bstd::copy\b", VulnType.UNSAFE_MEMORY_COPY),
    (r"\bcopy\b", VulnType.UNSAFE_MEMORY_COPY),
    (r"\bmemcmp\b", VulnType.OUT_OF_BOUNDS_READ),
    (r"\bsystem\b", VulnType.COMMAND_INJECTION),
    (r"\bpopen\b", VulnType.COMMAND_INJECTION),
    (r"\bsubprocess\b", VulnType.COMMAND_INJECTION),
    (r"\bexec\s*\(.*\+", VulnType.SQL_INJECTION),
    (r"\bexecute\s*\(.*\+", VulnType.SQL_INJECTION),
    (r"\beval\b", VulnType.CODE_EXECUTION),
    (r"\bpickle\b", VulnType.DESERIALIZATION),
    (r"\byaml\.load\b", VulnType.DESERIALIZATION),
    (r"\bopen\s*\(.*request\.", VulnType.PATH_TRAVERSAL),
    (r"\bsend_file\b", VulnType.PATH_TRAVERSAL),
    (r"\bdelete\s*\[\]", VulnType.RESOURCE_LEAK),
    (r"\bfree\s*\(", VulnType.USE_AFTER_FREE),
    (r"\bnew\s+", VulnType.RESOURCE_LEAK),
    (r"\bmalloc\b", VulnType.RESOURCE_LEAK),
]

# ---------------------------------------------------------------------------
# File-path pattern -> VulnType (for config files)
# ---------------------------------------------------------------------------
FILE_PATH_PATTERNS: list[tuple[str, VulnType]] = [
    (r"\.github/workflows/", VulnType.SUPPLY_CHAIN_CONFIG),
    (r"dependabot\.ya?ml", VulnType.SUPPLY_CHAIN_CONFIG),
    (r"\.github/dependabot", VulnType.SUPPLY_CHAIN_CONFIG),
    (r"renovate\.json", VulnType.SUPPLY_CHAIN_CONFIG),
    (r"\.circleci/config", VulnType.SUPPLY_CHAIN_CONFIG),
    (r"\.gitlab-ci\.yml", VulnType.SUPPLY_CHAIN_CONFIG),
    (r"Jenkinsfile", VulnType.SUPPLY_CHAIN_CONFIG),
    (r"\.travis\.yml", VulnType.SUPPLY_CHAIN_CONFIG),
]


class VulnerabilityTypeNormalizer:
    """Normalize LLM-generated type strings, tool rule IDs, and sink patterns
    into a single standard VulnType enum value."""

    def normalize(
        self,
        llm_type: str = "",
        tool: str = "",
        rule_id: str = "",
        rule_vuln_type: str = "",
        anchor_category: str = "",
        sink: str = "",
        file_path: str = "",
        category: str = "",
    ) -> VulnType:
        """Return the canonical VulnType for the given inputs.

        Resolution order:
        1. Tool-specific rule_id mapping.
        2. Explicit rule_vuln_type from rule files.
        3. Anchor category/risk-domain facts.
        4. File path patterns.
        5. Sink pattern regex matching.
        6. LLM type string keyword matching.
        7. Fallback to OTHER.
        """

        # 1. Tool rule-id → exact mapping
        if tool == "cppcheck" and rule_id:
            result = CPPCHECK_TYPE_MAP.get(rule_id)
            if result is not None:
                return result

        if tool in ("clang-tidy", "clang_tidy") and rule_id:
            result = CLANG_TIDY_TYPE_MAP.get(rule_id)
            if result is not None:
                return result

        # Gitleaks → always secret_leak
        if tool == "gitleaks":
            return VulnType.SECRET_LEAK

        # OSV / dependency scanners → dependency_vulnerability
        if tool in ("osv-scanner", "pip-audit", "npm-audit", "cargo-audit"):
            return VulnType.DEPENDENCY_VULNERABILITY

        # 2. Explicit rule vulnerability type.
        explicit_rule_type = self._match_llm_type(rule_vuln_type) if rule_vuln_type else None
        if explicit_rule_type is not None:
            return explicit_rule_type
        if rule_vuln_type:
            exact = VulnType.from_string(rule_vuln_type)
            if exact != VulnType.OTHER or rule_vuln_type == VulnType.OTHER.value:
                return exact

        # 3. Anchor category/risk-domain facts.
        fact_category = (anchor_category or category or "").strip().lower()
        if fact_category in {"secret", "secret_leak"}:
            return VulnType.SECRET_LEAK
        if fact_category in {"dependency", "dependency_vulnerability"}:
            return VulnType.DEPENDENCY_VULNERABILITY
        if fact_category in {"configuration", "configuration_security", "supply_chain_config"}:
            return VulnType.SUPPLY_CHAIN_CONFIG

        # 4. File path patterns.
        if file_path:
            for pattern, vuln_type in FILE_PATH_PATTERNS:
                if re.search(pattern, file_path.replace("\\", "/"), re.IGNORECASE):
                    return vuln_type

        # Rule IDs from non-mapped tools can still contain canonical keywords.
        if rule_id:
            result = self._match_llm_type(rule_id)
            if result is not None:
                return result

        # 5. Sink pattern regex matching.
        if sink:
            for pattern, vuln_type in SINK_PATTERN_MAP:
                if re.search(pattern, sink, re.IGNORECASE):
                    return vuln_type

        # 6. LLM type string keyword matching.
        if llm_type:
            result = self._match_llm_type(llm_type)
            if result is not None:
                return result

        # 7. Fallback.
        return VulnType.OTHER

    def _match_llm_type(self, text: str) -> VulnType | None:
        """Match a raw LLM type string against keyword lists."""
        lowered = text.lower().replace("_", " ").replace("-", " ")
        # Check supply chain FIRST (highest priority) before more generic patterns
        for keywords, vuln_type in LLM_TYPE_KEYWORDS:
            for keyword in keywords:
                if keyword in lowered:
                    return vuln_type
        return None

    def normalize_candidate(
        self,
        raw: dict[str, Any],
        slice_: Any = None,
        tool: str = "",
        rule_id: str = "",
    ) -> VulnType:
        """Normalize a candidate dictionary (from LLM or tool) to a VulnType."""
        llm_type = str(raw.get("vulnerability_type") or "")
        sink = str(raw.get("sink") or "")
        file_path = str(raw.get("file_path") or "")
        category = str(raw.get("category") or "")

        # Also try to get sink from the slice
        if not sink and slice_ is not None:
            sink = str(getattr(slice_, "sink", "") or "")

        if not file_path and slice_ is not None:
            file_path = str(getattr(slice_, "file_path", "") or "")

        return self.normalize(
            llm_type=llm_type,
            tool=tool,
            rule_id=rule_id,
            rule_vuln_type=str(raw.get("rule_vuln_type") or ""),
            anchor_category=str(raw.get("anchor_category") or ""),
            sink=sink,
            file_path=file_path,
            category=category,
        )
