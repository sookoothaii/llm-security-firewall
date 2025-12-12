"""
Fail-Closed Security Audit Script
==================================

Systematische Analyse aller Exception-Handler in Security-Komponenten
zur Identifikation von fail-open Patterns (Sicherheitsrisiko).

Usage:
    python scripts/audit_fail_closed.py

Output:
    - Liste aller Exception-Handler in Security-Komponenten
    - Identifikation von fail-open Patterns (return safe/allow bei Exception)
    - Empfehlungen für fail-closed Fixes
"""

import ast
from pathlib import Path
from typing import List
from dataclasses import dataclass


@dataclass
class ExceptionHandler:
    """Repräsentiert einen Exception-Handler in Security-Code."""

    file_path: str
    line_number: int
    exception_type: str
    handler_body: str
    is_fail_open: bool
    recommendation: str


class FailClosedAuditor(ast.NodeVisitor):
    """AST Visitor zur Analyse von Exception-Handlern."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.handlers: List[ExceptionHandler] = []
        self.current_line = 0

    def visit_ExceptHandler(self, node):
        """Analysiert Exception-Handler."""
        self.current_line = node.lineno

        # Extrahiere Exception-Typ
        exception_type = "Exception"
        if node.type:
            if isinstance(node.type, ast.Name):
                exception_type = node.type.id
            elif isinstance(node.type, ast.Tuple):
                exception_type = ", ".join(
                    elt.id if isinstance(elt, ast.Name) else "?"
                    for elt in node.type.elts
                )

        # Analysiere Handler-Body
        handler_code = (
            ast.unparse(node.body) if hasattr(ast, "unparse") else str(node.body)
        )
        is_fail_open = self._detect_fail_open(node.body)

        # Erstelle Empfehlung
        recommendation = self._generate_recommendation(is_fail_open, exception_type)

        self.handlers.append(
            ExceptionHandler(
                file_path=self.file_path,
                line_number=node.lineno,
                exception_type=exception_type,
                handler_body=handler_code[:200],  # Truncate
                is_fail_open=is_fail_open,
                recommendation=recommendation,
            )
        )

        self.generic_visit(node)

    def _detect_fail_open(self, body: List[ast.stmt]) -> bool:
        """Erkennt fail-open Patterns im Exception-Handler."""
        for stmt in body:
            # Pattern 1: return True / return (True, ...) / return {"allowed": True}
            if isinstance(stmt, ast.Return):
                if self._returns_safe(stmt.value):
                    return True

            # Pattern 2: pass (implizit fail-open)
            if isinstance(stmt, ast.Pass):
                return True

            # Pattern 3: logger.warning/error ohne Block
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                if self._is_logging_only(stmt.value):
                    # Prüfe ob danach return kommt
                    return True

        return False

    def _returns_safe(self, value) -> bool:
        """Prüft ob Return-Value "safe" bedeutet."""
        if value is None:
            return False

        # return True
        if isinstance(value, ast.Constant) and value.value is True:
            return True

        # return {"allowed": True}
        if isinstance(value, ast.Dict):
            for key, val in zip(value.keys, value.values):
                if (
                    isinstance(key, ast.Constant)
                    and key.value in ("allowed", "is_safe", "is_threat")
                    and isinstance(val, ast.Constant)
                    and val.value is True
                ):
                    return True

        # return (True, ...)
        if isinstance(value, ast.Tuple):
            for elt in value.elts:
                if isinstance(elt, ast.Constant) and elt.value is True:
                    return True

        return False

    def _is_logging_only(self, call: ast.Call) -> bool:
        """Prüft ob Call nur Logging ist."""
        if isinstance(call.func, ast.Attribute):
            if call.func.attr in ("warning", "error", "info", "debug"):
                return True
        return False

    def _generate_recommendation(self, is_fail_open: bool, exception_type: str) -> str:
        """Generiert Empfehlung für Exception-Handler."""
        if not is_fail_open:
            return "OK: Fail-closed oder neutral"

        return (
            f"FAIL-OPEN DETECTED: Exception-Handler gibt bei {exception_type} "
            "sicherheitskritische Operation frei. "
            "FIX: Ersetze durch fail-closed (raise SecurityException oder return block)."
        )


def audit_file(file_path: Path) -> List[ExceptionHandler]:
    """Analysiert eine Python-Datei auf fail-open Patterns."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        tree = ast.parse(content, filename=str(file_path))
        auditor = FailClosedAuditor(str(file_path))
        auditor.visit(tree)

        return auditor.handlers
    except Exception as e:
        print(f"ERROR parsing {file_path}: {e}")
        return []


def find_security_files(base_dir: Path) -> List[Path]:
    """Findet alle Security-relevanten Python-Dateien."""
    security_files = []

    # Security-relevante Verzeichnisse
    security_dirs = [
        "src/llm_firewall/core",
        "src/llm_firewall/safety",
        "src/llm_firewall/detectors",
        "src/llm_firewall/gates",
        "src/hak_gal/core",
        "src/hak_gal/layers",
    ]

    for sec_dir in security_dirs:
        dir_path = base_dir / sec_dir
        if dir_path.exists():
            for py_file in dir_path.rglob("*.py"):
                if not py_file.name.startswith("test_"):
                    security_files.append(py_file)

    return security_files


def main():
    """Hauptfunktion: Führt Fail-Closed-Audit durch."""
    base_dir = Path(__file__).parent.parent
    security_files = find_security_files(base_dir)

    print("=" * 80)
    print("FAIL-CLOSED SECURITY AUDIT")
    print("=" * 80)
    print(f"\nAnalysiere {len(security_files)} Security-Dateien...\n")

    all_handlers: List[ExceptionHandler] = []
    fail_open_count = 0

    for file_path in security_files:
        handlers = audit_file(file_path)
        all_handlers.extend(handlers)

        fail_open_in_file = [h for h in handlers if h.is_fail_open]
        if fail_open_in_file:
            fail_open_count += len(fail_open_in_file)
            print(f"\n[WARNING] {file_path.relative_to(base_dir)}")
            for handler in fail_open_in_file:
                print(f"   Line {handler.line_number}: {handler.exception_type}")
                print(f"   -> {handler.recommendation}")

    print("\n" + "=" * 80)
    print("ZUSAMMENFASSUNG")
    print("=" * 80)
    print(f"Gesamt Exception-Handler: {len(all_handlers)}")
    print(f"[WARNING] Fail-Open Patterns: {fail_open_count}")
    print(f"[OK] Fail-Closed/Neutral: {len(all_handlers) - fail_open_count}")

    if fail_open_count > 0:
        print("\n[CRITICAL] Fail-Open Patterns gefunden!")
        print("   Diese muessen auf fail-closed umgestellt werden.")
    else:
        print("\n[OK] Keine fail-open Patterns gefunden.")

    # Generiere Report-Datei
    report_path = base_dir / "docs" / "FAIL_CLOSED_AUDIT_REPORT.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# Fail-Closed Security Audit Report\n\n")
        f.write(f"**Datum:** {Path(__file__).stat().st_mtime}\n\n")
        f.write(f"**Analysierte Dateien:** {len(security_files)}\n")
        f.write(f"**Gesamt Exception-Handler:** {len(all_handlers)}\n")
        f.write(f"**Fail-Open Patterns:** {fail_open_count}\n\n")

        if fail_open_count > 0:
            f.write("## Fail-Open Patterns\n\n")
            for handler in all_handlers:
                if handler.is_fail_open:
                    f.write(f"### {handler.file_path}:{handler.line_number}\n\n")
                    f.write(f"- **Exception:** `{handler.exception_type}`\n")
                    f.write(f"- **Problem:** {handler.recommendation}\n")
                    f.write(f"- **Code:** `{handler.handler_body[:100]}...`\n\n")

    print(f"\n[REPORT] Detaillierter Report: {report_path.relative_to(base_dir)}")


if __name__ == "__main__":
    main()
