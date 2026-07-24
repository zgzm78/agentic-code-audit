from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CPP_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}
CONTROL_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "return",
    "sizeof",
    "static_cast",
    "reinterpret_cast",
    "const_cast",
    "dynamic_cast",
}
MEMORY_SINKS = {"memcpy", "std::memcpy", "memmove", "std::memmove", "strcpy", "strncpy", "std::copy", "copy"}


@dataclass
class FunctionBoundary:
    name: str
    file_path: str
    line_start: int
    line_end: int
    signature: str = ""
    language: str = ""
    parameters: list[str] = field(default_factory=list)

    @property
    def qualified_name(self) -> str:
        return self.name

    def contains(self, line: int) -> bool:
        return self.line_start <= line <= self.line_end


@dataclass
class CallEdgeSummary:
    caller: str
    callee: str
    file_path: str
    line: int
    resolution: str = "lexical"
    confidence: float = 0.55
    arguments: list[str] = field(default_factory=list)


@dataclass
class FunctionCodeSummary:
    name: str
    file_path: str
    line_start: int
    line_end: int
    signature: str = ""
    language: str = ""
    parameters: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    call_edges: list[CallEdgeSummary] = field(default_factory=list)
    field_reads: list[str] = field(default_factory=list)
    field_writes: list[str] = field(default_factory=list)
    guards: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)


@dataclass
class BackwardSliceSummary:
    sink: str
    sink_line: int
    sink_args: list[str] = field(default_factory=list)
    role_args: dict[str, str] = field(default_factory=dict)
    dependencies: list[dict[str, Any]] = field(default_factory=list)
    field_reads: list[str] = field(default_factory=list)
    field_writes: list[str] = field(default_factory=list)
    guards: list[str] = field(default_factory=list)
    missing_guards: list[str] = field(default_factory=list)
    unresolved_symbols: list[str] = field(default_factory=list)
    summary_steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sink": self.sink,
            "sink_line": self.sink_line,
            "sink_args": self.sink_args,
            "role_args": self.role_args,
            "dependencies": self.dependencies,
            "field_reads": self.field_reads,
            "field_writes": self.field_writes,
            "guards": self.guards,
            "missing_guards": self.missing_guards,
            "unresolved_symbols": self.unresolved_symbols,
            "summary_steps": self.summary_steps,
        }


class CppFunctionIndexer:
    """Best-effort C/C++ function boundary and summary builder.

    The indexer deliberately avoids compile-database assumptions. It is not a
    full C++ parser, but it is strict about brace ownership so adjacent
    functions do not bleed into each other. This directly protects sink
    attribution and report titles.
    """

    def boundaries_for_file(self, path: Path, rel_path: str = "") -> list[FunctionBoundary]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        suffix = path.suffix.lower()
        if suffix not in CPP_SUFFIXES:
            return []
        return self.boundaries_from_text(text, rel_path or path.as_posix(), self._language_for_suffix(suffix))

    def boundaries_from_text(self, text: str, file_path: str, language: str = "C++") -> list[FunctionBoundary]:
        lines = text.splitlines()
        output: list[FunctionBoundary] = []
        index = 0
        while index < len(lines):
            candidate = self._function_at(lines, index + 1, file_path, language)
            if candidate is None:
                index += 1
                continue
            output.append(candidate)
            index = max(index + 1, candidate.line_end)
        return output

    def boundary_at(self, path: Path, line_number: int, rel_path: str = "") -> FunctionBoundary | None:
        boundaries = self.boundaries_for_file(path, rel_path)
        return next((item for item in boundaries if item.contains(line_number)), None)

    def summarize(self, boundary: FunctionBoundary, lines: list[str]) -> FunctionCodeSummary:
        body = self._body_lines(boundary, lines)
        calls: list[str] = []
        call_edges: list[CallEdgeSummary] = []
        field_reads: list[str] = []
        field_writes: list[str] = []
        guards: list[str] = []
        sinks: list[str] = []
        sources: list[str] = []
        for offset, line in enumerate(body, start=boundary.line_start):
            stripped = line.strip()
            if re.match(r"^(if|while|for|switch|case|assert|enforce)\b", stripped):
                guards.append(stripped)
            for call in self.calls_in_line(stripped):
                if call == boundary.name:
                    continue
                calls.append(call)
                call_edges.append(
                    CallEdgeSummary(
                        caller=boundary.name,
                        callee=call,
                        file_path=boundary.file_path,
                        line=offset,
                        arguments=split_call_args(extract_call_args(stripped, call)),
                    )
                )
                if self._canonical_call(call) in MEMORY_SINKS:
                    sinks.append(call)
                if self._is_source_call(call):
                    sources.append(call)
            field_reads.extend(self.field_accesses(stripped))
            field_writes.extend(self.field_writes(stripped))
        return FunctionCodeSummary(
            name=boundary.name,
            file_path=boundary.file_path,
            line_start=boundary.line_start,
            line_end=boundary.line_end,
            signature=boundary.signature,
            language=boundary.language,
            parameters=list(boundary.parameters),
            calls=list(dict.fromkeys(calls))[:40],
            call_edges=call_edges[:80],
            field_reads=list(dict.fromkeys(field_reads))[:40],
            field_writes=list(dict.fromkeys(field_writes))[:40],
            guards=list(dict.fromkeys(guards))[:30],
            sinks=list(dict.fromkeys(sinks))[:20],
            sources=list(dict.fromkeys(sources))[:20],
        )

    def backward_slice(
        self,
        boundary: FunctionBoundary,
        lines: list[str],
        *,
        sink_line: int,
        sink: str,
    ) -> BackwardSliceSummary:
        sink_text = lines[sink_line - 1] if 1 <= sink_line <= len(lines) else ""
        args = split_call_args(extract_call_args(sink_text, sink))
        role_args = self._role_args(sink, args)
        assignments = self._assignments_before(boundary, lines, sink_line)
        guards = [
            line.strip()
            for line in lines[boundary.line_start - 1 : max(boundary.line_start - 1, sink_line - 1)]
            if re.match(r"^\s*(if|while|for|switch|assert|enforce)\b", line)
        ]
        dependencies: list[dict[str, Any]] = []
        unresolved: list[str] = []
        seen: set[str] = set()
        for role, expression in role_args.items():
            self._trace_expression(
                role,
                expression,
                assignments,
                dependencies,
                unresolved,
                seen,
                depth=0,
            )
        dep_text = "\n".join(str(item.get("expression", "")) for item in dependencies)
        combined = "\n".join([sink_text, dep_text, *guards])
        field_reads = list(dict.fromkeys(self.field_accesses(combined)))[:40]
        field_writes = list(dict.fromkeys(self.field_writes("\n".join(lines[boundary.line_start - 1 : boundary.line_end]))))[:40]
        missing_guards = self._missing_guard_facts(sink, role_args, guards, dep_text)
        steps = self._summary_steps(role_args, dependencies, missing_guards)
        return BackwardSliceSummary(
            sink=sink,
            sink_line=sink_line,
            sink_args=args,
            role_args=role_args,
            dependencies=dependencies[:80],
            field_reads=field_reads,
            field_writes=field_writes,
            guards=list(dict.fromkeys(guards))[:30],
            missing_guards=missing_guards,
            unresolved_symbols=list(dict.fromkeys(unresolved))[:30],
            summary_steps=steps,
        )

    def calls_in_line(self, line: str) -> list[str]:
        output: list[str] = []
        for match in re.finditer(r"(?<![A-Za-z0-9_])([A-Za-z_~][A-Za-z0-9_:~]*(?:\s*(?:->|\.)\s*[A-Za-z_~][A-Za-z0-9_:~]*)?)\s*\(", line):
            name = re.sub(r"\s+", "", match.group(1))
            base = name.split("::")[-1].split("->")[-1].split(".")[-1]
            if base in CONTROL_KEYWORDS:
                continue
            output.append(name)
        return list(dict.fromkeys(output))

    def field_accesses(self, text: str) -> list[str]:
        patterns = [
            r"\bp_->[A-Za-z_][A-Za-z0-9_]*",
            r"\bthis->[A-Za-z_][A-Za-z0-9_]*",
            r"\b[A-Za-z_][A-Za-z0-9_]*\s*(?:->|\.)\s*[A-Za-z_][A-Za-z0-9_]*",
            r"\b[A-Za-z_][A-Za-z0-9_]*_\[[^\]]+\]\s*\.\s*[A-Za-z_][A-Za-z0-9_]*",
        ]
        values: list[str] = []
        for pattern in patterns:
            values.extend(re.sub(r"\s+", "", item) for item in re.findall(pattern, text))
        return list(dict.fromkeys(values))

    def field_writes(self, text: str) -> list[str]:
        values: list[str] = []
        for match in re.finditer(r"((?:p_|this|[A-Za-z_][A-Za-z0-9_]*)->\s*[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)\s*(?:=|\+=|-=|\+\+|--)", text):
            values.append(re.sub(r"\s+", "", match.group(1)))
        return list(dict.fromkeys(values))

    def _function_at(
        self,
        lines: list[str],
        line_number: int,
        file_path: str,
        language: str,
    ) -> FunctionBoundary | None:
        start_index = line_number - 1
        first = lines[start_index].strip()
        if not first or first.startswith(("#", "//", "/*", "*")):
            return None
        signature_lines: list[str] = []
        brace_line = 0
        for index in range(start_index, min(len(lines), start_index + 8)):
            piece = strip_cpp_line_comment(lines[index]).strip()
            if not piece:
                continue
            signature_lines.append(piece)
            if "{" in piece:
                brace_line = index + 1
                break
            if ";" in piece and not piece.rstrip().endswith(":"):
                return None
        if not brace_line:
            return None
        signature = " ".join(signature_lines)
        before_brace = signature.split("{", 1)[0].strip()
        if not self._looks_like_function_signature(before_brace):
            return None
        name = self._function_name(before_brace)
        if not name:
            return None
        end = self._matching_brace_end(lines, brace_line)
        if end <= brace_line:
            return None
        return FunctionBoundary(
            name=name,
            file_path=file_path,
            line_start=line_number,
            line_end=end,
            signature=before_brace,
            language=language,
            parameters=parameters_from_signature(before_brace),
        )

    def _looks_like_function_signature(self, signature: str) -> bool:
        lowered = signature.strip().lower()
        if not lowered or "(" not in lowered or ")" not in lowered:
            return False
        prefix = lowered.split("(", 1)[0].strip()
        last = prefix.split()[-1].split("::")[-1] if prefix.split() else ""
        if last in CONTROL_KEYWORDS:
            return False
        if prefix.endswith(("=", "+", "-", "*", "/", ",")):
            return False
        if re.search(r"\b(if|for|while|switch|catch)\s*$", prefix):
            return False
        return True

    def _function_name(self, signature: str) -> str:
        before = signature.split("(", 1)[0].strip()
        before = re.sub(r"\b(?:static|inline|virtual|constexpr|consteval|explicit|friend|extern)\b", " ", before)
        before = re.sub(r"\s+", " ", before).strip()
        if not before:
            return ""
        token = before.split()[-1].strip("*&")
        token = token.removeprefix("(*)")
        if token in CONTROL_KEYWORDS:
            return ""
        return token

    def _matching_brace_end(self, lines: list[str], brace_line: int) -> int:
        depth = 0
        opened = False
        for index in range(brace_line - 1, len(lines)):
            line = strip_cpp_line_comment(lines[index])
            for char in line:
                if char == "{":
                    depth += 1
                    opened = True
                elif char == "}":
                    depth -= 1
                    if opened and depth == 0:
                        return index + 1
        return len(lines)

    def _body_lines(self, boundary: FunctionBoundary, lines: list[str]) -> list[str]:
        return lines[boundary.line_start - 1 : boundary.line_end]

    def _assignments_before(
        self,
        boundary: FunctionBoundary,
        lines: list[str],
        sink_line: int,
    ) -> dict[str, dict[str, Any]]:
        assignments: dict[str, dict[str, Any]] = {}
        for number in range(boundary.line_start, min(boundary.line_end, sink_line - 1) + 1):
            stripped = strip_cpp_line_comment(lines[number - 1]).strip()
            match = re.match(
                r"(?:const\s+)?(?:auto|size_t|ssize_t|int|long|bool|char|byte|uint\w*|std::\w+(?:<[^>]+>)?|[A-Za-z_:][A-Za-z0-9_:<>*&\s]+)?\s*"
                r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?);?\s*$",
                stripped,
            )
            if match:
                variable = match.group(1)
                if variable not in CONTROL_KEYWORDS:
                    assignments[variable] = {"line": number, "expression": match.group(2).strip(), "text": stripped}
        return assignments

    def _trace_expression(
        self,
        role: str,
        expression: str,
        assignments: dict[str, dict[str, Any]],
        dependencies: list[dict[str, Any]],
        unresolved: list[str],
        seen: set[str],
        *,
        depth: int,
    ) -> None:
        if depth > 8:
            return
        for symbol in identifiers(expression):
            if symbol in CONTROL_KEYWORDS or symbol in CPP_TYPES:
                continue
            key = f"{role}:{symbol}"
            if key in seen:
                continue
            seen.add(key)
            assignment = assignments.get(symbol)
            if not assignment:
                unresolved.append(symbol)
                continue
            dependencies.append(
                {
                    "role": role,
                    "symbol": symbol,
                    "line": assignment["line"],
                    "expression": assignment["expression"],
                    "text": assignment["text"],
                }
            )
            self._trace_expression(
                role,
                str(assignment["expression"]),
                assignments,
                dependencies,
                unresolved,
                seen,
                depth=depth + 1,
            )

    def _role_args(self, sink: str, args: list[str]) -> dict[str, str]:
        canonical = self._canonical_call(sink)
        if canonical in {"memcpy", "std::memcpy", "memmove", "std::memmove"} and len(args) >= 3:
            return {"destination": args[0], "source": args[1], "length": args[2]}
        if canonical in {"strcpy", "strncpy"} and len(args) >= 2:
            output = {"destination": args[0], "source": args[1]}
            if len(args) >= 3:
                output["length"] = args[2]
            return output
        return {f"arg{index}": value for index, value in enumerate(args)}

    def _missing_guard_facts(
        self,
        sink: str,
        role_args: dict[str, str],
        guards: list[str],
        dependency_text: str,
    ) -> list[str]:
        canonical = self._canonical_call(sink)
        if canonical not in MEMORY_SINKS:
            return []
        guard_text = "\n".join(guards).lower()
        length = role_args.get("length", "").lower()
        source = role_args.get("source", "").lower()
        combined = f"{length}\n{source}\n{dependency_text}".lower()
        missing: list[str] = []
        if ("getdata" in combined or "data" in source) and "getsize" not in combined and "getsize" not in guard_text:
            missing.append("actual source buffer size check")
        if length and not any(token in guard_text for token in ("<", "<=", "min", "size", "length", "bound", "assert", "enforce")):
            missing.append("length or bounds check")
        if "blocksize_" in combined and "getsize" not in combined:
            missing.append("block size vs actual block data size check")
        return list(dict.fromkeys(missing))

    def _summary_steps(
        self,
        role_args: dict[str, str],
        dependencies: list[dict[str, Any]],
        missing_guards: list[str],
    ) -> list[str]:
        steps = [f"{role}={expr}" for role, expr in role_args.items()]
        for item in dependencies[:12]:
            steps.append(f"{item['symbol']} <- {item['expression']} @ {item['line']}")
        for guard in missing_guards:
            steps.append(f"missing_guard:{guard}")
        return steps[:30]

    def _canonical_call(self, value: str) -> str:
        compact = re.sub(r"\s+", "", value)
        compact = compact.split("->")[-1].split(".")[-1]
        return compact

    def _is_source_call(self, value: str) -> bool:
        return self._canonical_call(value) in {"read", "recv", "fread", "getDataByRange"}

    def _language_for_suffix(self, suffix: str) -> str:
        return "C" if suffix == ".c" else "C++"


CPP_TYPES = {
    "auto",
    "size_t",
    "ssize_t",
    "int",
    "long",
    "bool",
    "char",
    "byte",
    "const",
    "unsigned",
    "signed",
    "return",
    "std",
    "string",
}


def strip_cpp_line_comment(line: str) -> str:
    return re.sub(r"//.*", "", line)


def parameters_from_signature(signature: str) -> list[str]:
    args = extract_call_args(signature, "")
    output: list[str] = []
    for item in split_call_args(args):
        left = item.split("=", 1)[0].strip()
        if not left or left == "void":
            continue
        tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", left)
        if tokens:
            output.append(tokens[-1])
    return output


def extract_call_args(text: str, sink: str) -> str:
    if sink:
        names = [re.escape(sink), re.escape(sink.replace("std::", ""))]
        match = re.search(rf"(?:{'|'.join(names)})\s*\((.*)\)", text)
        if match:
            return match.group(1)
    start = text.find("(")
    if start < 0:
        return ""
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1 : index]
    return text[start + 1 :]


def split_call_args(value: str) -> list[str]:
    args: list[str] = []
    current: list[str] = []
    depth = 0
    for char in value:
        if char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            item = "".join(current).strip()
            if item:
                args.append(item)
            current = []
            continue
        current.append(char)
    item = "".join(current).strip()
    if item:
        args.append(item)
    return args


def identifiers(expression: str) -> list[str]:
    values = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expression)
    return list(dict.fromkeys(value for value in values if value not in CPP_TYPES))


def stable_id(*parts: object) -> str:
    return hashlib.sha1(":".join(str(part) for part in parts).encode("utf-8")).hexdigest()[:12]
