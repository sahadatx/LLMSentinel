"""Conservative Python AST taint scanner with same-module helper summaries."""

from __future__ import annotations

import ast
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from sentinel.scanner.filesystem import FileInventory, InventoryIssue, inventory_files


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    path: str
    line: int
    cwe: str
    snippet: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


SOURCES = (
    "input",
    "request.args",
    "request.form",
    "request.values",
    "request.json",
    "request.get_json",
    "request.get_data",
    "request.data",
    "request.query_params",
    "request.path_params",
    "request.body",
)
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_SOURCE_FILES = 5_000
MAX_TOTAL_SOURCE_BYTES = 256 * 1024 * 1024
MAX_DIRECTORY_ENTRIES = 100_000
MAX_AST_NODES = 250_000
MAX_TAINT_ANALYSIS_WORK = 2_000_000
SINKS: tuple[tuple[str, str, str], ...] = (
    ("eval", "python.dynamic-eval", "CWE-95"),
    ("exec", "python.dynamic-exec", "CWE-95"),
    ("os.system", "python.os-system", "CWE-78"),
    ("subprocess.Popen", "python.subprocess", "CWE-78"),
    ("subprocess.run", "python.subprocess", "CWE-78"),
    ("pickle.loads", "python.unsafe-deserialization", "CWE-502"),
    ("yaml.load", "python.unsafe-yaml", "CWE-502"),
    ("SystemMessage", "llm.untrusted-system-prompt", "CWE-74"),
    ("system_prompt", "llm.untrusted-system-prompt", "CWE-74"),
    ("ChatPromptTemplate.from_messages", "llm.prompt-construction", "CWE-74"),
)


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    return ""


def _names_in_target(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for elt in target.elts for name in _names_in_target(elt)]
    return []


class _Analyzer(ast.NodeVisitor):
    def __init__(self, path: Path, source: str, summaries: dict[str, dict[str, Any]], seed: set[str] | None = None):
        self.path = path
        self.source = source
        self.lines = source.splitlines()
        self.summaries = summaries
        self.env: dict[str, set[str]] = {name: {"arg"} for name in (seed or set())}
        self.findings: list[Finding] = []
        self.sink_params: set[str] = set()
        self.return_tainted = False
        self.in_function = False

    def taint(self, node: ast.AST) -> set[str]:
        if isinstance(node, ast.Name):
            return set(self.env.get(node.id, set()))
        if isinstance(node, ast.Constant):
            return set()
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return set().union(*(self.taint(item) for item in node.elts)) if node.elts else set()
        if isinstance(node, ast.Dict):
            return set().union(*(self.taint(item) for item in [*node.keys, *node.values] if item is not None))
        if isinstance(node, ast.BinOp):
            return self.taint(node.left) | self.taint(node.right)
        if isinstance(node, ast.JoinedStr):
            return set().union(*(self.taint(item) for item in node.values))
        if isinstance(node, ast.FormattedValue):
            return self.taint(node.value)
        if isinstance(node, ast.IfExp):
            return self.taint(node.body) | self.taint(node.orelse)
        if isinstance(node, ast.Call):
            name = _name(node.func)
            arg_taints = [self.taint(arg) for arg in node.args]
            result = set().union(*arg_taints) if arg_taints else set()
            if any(name == source or name.startswith(source + ".") for source in SOURCES):
                result.add("source")
            summary = self.summaries.get(name.split(".")[-1])
            if summary:
                for index in summary["sink_args"]:
                    if index < len(arg_taints) and arg_taints[index]:
                        self.sink_params.update(arg_taints[index])
                        self._add("python.interprocedural-taint", "HIGH", f"Untrusted value reaches a risky helper ({name}).", node, "CWE-74")
                if not summary["returns_tainted"]:
                    result = set()
            if isinstance(node.func, ast.Attribute):
                result |= self.taint(node.func.value)
            return result
        if isinstance(node, ast.Attribute):
            name = _name(node)
            result = self.taint(node.value)
            if any(name == source or name.startswith(source + ".") for source in SOURCES):
                result.add("source")
            return result
        if isinstance(node, ast.Subscript):
            return self.taint(node.value) | self.taint(node.slice)
        if isinstance(node, ast.UnaryOp):
            return self.taint(node.operand)
        return set()

    def _sink(self, name: str) -> tuple[str, str] | None:
        for pattern, rule, cwe in SINKS:
            if name == pattern or name.endswith("." + pattern):
                return rule, cwe
        return None

    def _add(self, rule: str, severity: str, message: str, node: ast.AST, cwe: str) -> None:
        line = getattr(node, "lineno", 1)
        snippet = self.lines[line - 1].strip() if line <= len(self.lines) else ""
        finding = Finding(rule, severity, message, str(self.path), line, cwe, snippet[:240])
        if not any(old.rule_id == rule and old.line == line and old.path == str(self.path) for old in self.findings):
            self.findings.append(finding)

    def visit_Assign(self, node: ast.Assign) -> None:
        value_taint = self.taint(node.value)
        for target in node.targets:
            for name in _names_in_target(target):
                self.env[name] = set(value_taint)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        value_taint = self.taint(node.value) if node.value else set()
        for name in _names_in_target(node.target):
            self.env[name] = set(value_taint)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        for name in _names_in_target(node.target):
            self.env[name] = self.taint(node.value)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None and self.taint(node.value):
            self.return_tainted = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _name(node.func)
        sink = self._sink(name)
        if sink:
            tainted = set().union(*(self.taint(arg) for arg in node.args)) if node.args else set()
            tainted |= set().union(*(self.taint(keyword.value) for keyword in node.keywords)) if node.keywords else set()
            if tainted:
                self.sink_params.update(tainted)
                self._add(sink[0], "CRITICAL" if sink[0] in {"python.dynamic-eval", "python.dynamic-exec", "python.os-system", "python.subprocess", "python.unsafe-deserialization"} else "HIGH", f"Untrusted data reaches {name}.", node, sink[1])
        self.generic_visit(node)


def _function_params(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    args = [*function.args.posonlyargs, *function.args.args]
    if function.args.vararg:
        args.append(function.args.vararg)
    args.extend(function.args.kwonlyargs)
    if function.args.kwarg:
        args.append(function.args.kwarg)
    return [arg.arg for arg in args]


def scan_python_file(path: Path) -> list[Finding]:
    try:
        if path.is_symlink():
            return [Finding("source.symlink-skipped", "INFO", "Symbolic links are not followed by the scanner.", str(path), 1, "CWE-59")]
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            if os.fstat(stream.fileno()).st_size > MAX_SOURCE_BYTES:
                return [Finding("source.file-too-large", "MEDIUM", "Source exceeds the 2 MiB per-file analysis limit.", str(path), 1, "CWE-789")]
            raw_source = stream.read(MAX_SOURCE_BYTES + 1)
        if len(raw_source) > MAX_SOURCE_BYTES:
            return [Finding("source.file-too-large", "MEDIUM", "Source exceeds the 2 MiB per-file analysis limit.", str(path), 1, "CWE-789")]
        source = raw_source.decode("utf-8")
        tree = ast.parse(source, filename=str(path))
    except OSError as exc:
        return [Finding("source.read-error", "LOW", f"Could not read source file: {type(exc).__name__}.", str(path), 1, "CWE-732")]
    except UnicodeDecodeError:
        return [Finding("source.encoding-error", "LOW", "Source is not valid UTF-8 and was not analyzed.", str(path), 1, "CWE-176")]
    except SyntaxError as exc:
        return [Finding("source.parse-error", "LOW", f"Python syntax error: {exc.msg}.", str(path), exc.lineno or 1, "CWE-693")]
    except RecursionError:
        return [Finding("source.parse-limit", "MEDIUM", "Source nesting exceeded the parser safety limit; file was not analyzed.", str(path), 1, "CWE-789")]

    node_count = 0
    pending: list[ast.AST] = [tree]
    while pending:
        node = pending.pop()
        node_count += 1
        if node_count > MAX_AST_NODES:
            return [Finding("source.ast-node-limit", "MEDIUM", f"Source exceeds the {MAX_AST_NODES:,} AST node analysis limit; file was not analyzed.", str(path), 1, "CWE-789")]
        pending.extend(ast.iter_child_nodes(node))

    try:
        return _analyze_tree(path, source, tree, node_count)
    except RecursionError:
        return [Finding("source.analysis-limit", "MEDIUM", "Taint analysis exceeded the recursion safety limit; file was not fully analyzed.", str(path), 1, "CWE-789")]


def _analyze_tree(path: Path, source: str, tree: ast.Module, node_count: int) -> list[Finding]:
    functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    parameters = {id(function): _function_params(function) for function in functions}
    summary_passes = min(8, len(functions) + 1)
    estimated_work = node_count
    for function in functions:
        body_nodes = 0
        pending: list[ast.AST] = list(function.body)
        while pending:
            node = pending.pop()
            body_nodes += 1
            pending.extend(ast.iter_child_nodes(node))
        parameter_count = len(parameters[id(function)])
        estimated_work += body_nodes + body_nodes * parameter_count * summary_passes
        if estimated_work > MAX_TAINT_ANALYSIS_WORK:
            return [Finding("source.analysis-work-limit", "MEDIUM", f"Estimated taint analysis exceeds the {MAX_TAINT_ANALYSIS_WORK:,} node-visit budget; file was not analyzed.", str(path), 1, "CWE-789")]
    summaries: dict[str, dict[str, Any]] = {fn.name: {"sink_args": set(), "returns_tainted": False} for fn in functions}
    # Iterate so helper-to-helper flows in this module become visible.
    for _ in range(min(8, len(functions) + 1)):
        changed = False
        for fn in functions:
            params = parameters[id(fn)]
            sink_args: set[int] = set()
            returns_tainted = False
            for index, param in enumerate(params):
                analyzer = _Analyzer(path, source, summaries, {param})
                for statement in fn.body:
                    analyzer.visit(statement)
                if "arg" in analyzer.sink_params:
                    sink_args.add(index)
                returns_tainted |= analyzer.return_tainted
            next_summary = {"sink_args": sink_args, "returns_tainted": returns_tainted}
            old = summaries[fn.name]
            if old["sink_args"] != sink_args or old["returns_tainted"] != returns_tainted:
                summaries[fn.name] = next_summary
                changed = True
        if not changed:
            break
    analyzer = _Analyzer(path, source, summaries)
    for statement in tree.body:
        if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            analyzer.visit(statement)
    for fn in functions:
        visitor = _Analyzer(path, source, summaries)
        for statement in fn.body:
            visitor.visit(statement)
        analyzer.findings.extend(visitor.findings)
    unique = {(finding.rule_id, finding.line, finding.path): finding for finding in analyzer.findings}
    return sorted(unique.values(), key=lambda item: (item.path, item.line, item.rule_id))


def scan_path(path: str | Path) -> list[Finding]:
    root = Path(path)
    inventory = inventory_files(
        root,
        {".py"},
        max_files=MAX_SOURCE_FILES,
        max_entries=MAX_DIRECTORY_ENTRIES,
    )
    issue = _inventory_finding(inventory, "source")
    if issue:
        return [issue]
    findings: list[Finding] = []
    total_bytes = 0
    for file in inventory.files:
        try:
            size = file.stat().st_size
        except OSError:
            findings.extend(scan_python_file(file))
            continue
        if total_bytes + size > MAX_TOTAL_SOURCE_BYTES:
            findings.append(Finding("source.total-byte-limit", "MEDIUM", "Directory tree exceeds the 256 MiB aggregate source analysis limit; remaining files were not analyzed.", str(root), 1, "CWE-789"))
            break
        total_bytes += size
        findings.extend(scan_python_file(file))
    return findings


def _inventory_finding(inventory: FileInventory, prefix: str) -> Finding | None:
    issue: InventoryIssue | None = inventory.issue
    if issue is None:
        return None
    if issue.code in {"entry_limit", "file_limit"}:
        severity, cwe = "MEDIUM", "CWE-789"
    elif issue.code == "symlink":
        severity, cwe = "INFO", "CWE-59"
    else:
        severity, cwe = "LOW", "CWE-732"
    return Finding(f"{prefix}.{issue.code.replace('_', '-')}", severity, issue.message, str(issue.path), 1, cwe)
