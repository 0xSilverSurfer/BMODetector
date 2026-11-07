import json

from conftest import run_cli


def test_vulnerable_lab_is_detected_and_exit_code_1(lab, tmp_path):
    r = run_cli("-t", f"{lab}/v1/chat", "--no-llm", "--fail-on-vuln", "-o", str(tmp_path))
    assert r.returncode == 1
    res = json.loads((tmp_path / "results.json").read_text())
    assert res["summary"]["findings"] == 10 and res["summary"]["inconclusive"] == 0
    for name in ("audit_report.pdf", "dashboard.html", "guardrails.yaml", "audit_results.sarif", "siem_wazuh.cef",
                 "BMODetector_middleware.py", "nuclei_llm_audit.yaml", "evidence.jsonl"):
        assert (tmp_path / name).exists(), name


def test_no_llm_never_contacts_ollama_or_leaks_error_text(lab, tmp_path):
    r = run_cli("-t", f"{lab}/v1/chat", "--no-llm", "-o", str(tmp_path))
    blob = r.stdout + r.stderr + (tmp_path / "results.json").read_text() + (tmp_path / "evidence.jsonl").read_text()
    assert "Ollama Error" not in blob


def test_dead_endpoint_is_not_reported_as_secure(lab, tmp_path):
    r = run_cli("-t", f"{lab}/does/not/exist", "--no-llm", "--fail-on-vuln", "-o", str(tmp_path))
    assert r.returncode == 2
    res = json.loads((tmp_path / "results.json").read_text())
    assert res["summary"]["overall"] is None and all(x["status"] == "ERROR" for x in res["results"])


def test_missing_key_is_inconclusive_and_valid_key_passes(lab, tmp_path):
    r = run_cli("-t", f"{lab}/v1/chat/secured", "--no-llm", "--fail-on-vuln", "-o", str(tmp_path / "a"))
    assert r.returncode == 2
    r = run_cli("-t", f"{lab}/v1/chat/secured", "--no-llm", "--fail-on-vuln", "--recon", "-o", str(tmp_path / "b"), env={"BMO_API_KEY": "k"})
    assert r.returncode == 0, r.stdout[-800:]
    res = json.loads((tmp_path / "b" / "results.json").read_text())
    assert res["summary"]["findings"] == 0 and res["summary"]["overall"] >= 80


def test_json_format_is_pure_json_on_stdout(lab, tmp_path):
    r = run_cli("-t", f"{lab}/v1/chat", "--no-llm", "-n", "2", "-f", "json", "-o", str(tmp_path))
    doc = json.loads(r.stdout)
    assert len(doc["results"]) == 2 and "summary" in doc


def test_openai_format_and_unbounded_output(lab, tmp_path):
    r = run_cli("-t", f"{lab}/v1/chat/completions", "--api-type", "openai", "--target-model", "mock", "--no-llm",
                "--only", "LLM01,LLM10", "-f", "json", "-o", str(tmp_path))
    res = {x["owasp_id"]: x for x in json.loads(r.stdout)["results"]}
    assert res["LLM01"]["status"] == "FAIL" and res["LLM10"]["status"] in ("WARN", "FAIL")


def test_rate_limit_429(lab, tmp_path):
    r = run_cli("-t", f"{lab}/v1/chat/limited", "--no-llm", "--only", "LLM10,LLM01", "-f", "json", "-o", str(tmp_path))
    res = {x["owasp_id"]: x["status"] for x in json.loads(r.stdout)["results"]}
    assert res == {"LLM01": "ERROR", "LLM10": "PASS"}


def test_remote_target_requires_authorization_flag():
    r = run_cli("-t", "https://example.com/api", "--no-llm")
    assert r.returncode == 2 and "i-have-authorization" in r.stdout + r.stderr


def test_unknown_module_and_bad_options_exit_2(lab):
    assert run_cli("-t", f"{lab}/v1/chat", "--only", "LLM99").returncode == 2
    assert run_cli("-t", f"{lab}/v1/chat", "--api-type", "nope").returncode == 2
    assert run_cli("-t", f"{lab}/v1/chat", "-H", "bad-header").returncode == 2


def test_hostile_reply_with_rich_markup_does_not_crash(tmp_path):
    from rich.console import Console
    from rich.markup import escape
    from rich.table import Table
    t = Table()
    t.add_row(escape("hello [/bold] [red]x"))
    Console(file=open(tmp_path / "o", "w")).print(t)
