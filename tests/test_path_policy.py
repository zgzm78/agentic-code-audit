from pathlib import Path

from agentic_code_audit.agents.mining import DangerousFunctionLocator
from agentic_code_audit.path_policy import PathPolicy


def test_path_policy_classifies_generated_vendor_and_low_priority_paths() -> None:
    policy = PathPolicy()

    assert policy.classify("public/js/app.min.js").action == "exclude"
    assert policy.classify("vendor/library/parser.c").action == "exclude"
    assert policy.classify("tests/parser_test.py").action == "deprioritize"
    assert policy.classify("src/parser.c").action == "include"


def test_dangerous_locator_ignores_minified_vendor_and_test_sources(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "public").mkdir()
    (tmp_path / "vendor" / "lib").mkdir(parents=True)
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "app.js").write_text("function run(x) { return eval(x); }\n", encoding="utf-8")
    (tmp_path / "public" / "app.min.js").write_text("function x(a){return eval(a)}\n", encoding="utf-8")
    (tmp_path / "vendor" / "lib" / "copy.c").write_text("void f(){strcpy(a,b);}\n", encoding="utf-8")
    (tmp_path / "tests" / "test_app.py").write_text("eval(input())\n", encoding="utf-8")

    anchors = DangerousFunctionLocator().locate(tmp_path, [])

    assert anchors
    assert {anchor.file_path for anchor in anchors} == {"src/app.js"}
