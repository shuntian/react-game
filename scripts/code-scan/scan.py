"""Run the independent security checks and publish only selected report fields."""

import argparse
from collections import Counter
from html import escape
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
RULES = Path(__file__).with_name("semgrep.yml").relative_to(ROOT)
SEVERITIES = ("critical", "high", "medium", "low", "info")
BLOCKING = {"critical", "high"}


def semgrep_findings(data):
    return [
        {
            "severity": {"ERROR": "high", "WARNING": "medium", "INFO": "low"}[
                item["extra"]["severity"]
            ],
            "path": item["path"],
            "line": item["start"]["line"],
            "rule": item["check_id"],
            "message": item["extra"]["message"],
        }
        for item in data["results"]
    ]


def gitleaks_findings(data):
    # The JSON reporter encodes a nil slice as null when the scan finds no leaks.
    return [
        {
            "severity": "high",
            "path": item["File"],
            "line": item["StartLine"],
            "rule": item["RuleID"],
            "commit": item["Commit"],
        }
        for item in ([] if data is None else data)
    ]


def npm_findings(data):
    return [
        {
            "severity": (
                "medium" if item["severity"] == "moderate" else item["severity"]
            ),
            "package": name,
            "range": item["range"],
            "via": [
                (
                    {"title": entry["title"], "url": entry["url"]}
                    if isinstance(entry, dict)
                    else {"package": entry}
                )
                for entry in item["via"]
            ],
            "fix_available": item["fixAvailable"],
        }
        for name, item in data["vulnerabilities"].items()
    ]


def run_scanner(command, parse_findings, finding_exit=None):
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
            check=False,
        )
    except FileNotFoundError:
        return {"error": "scanner not installed"}
    except subprocess.TimeoutExpired:
        return {"error": "scanner timed out"}
    except OSError:
        return {"error": "could not start scanner"}

    # Scanner logs and raw JSON may contain source excerpts or matched secrets.
    try:
        data = json.loads(result.stdout)
    except ValueError:
        return {"error": f"invalid JSON (exit {result.returncode})"}

    if isinstance(data, dict) and ("error" in data or data.get("errors")):
        error = data.get("error")
        code = error.get("code") if isinstance(error, dict) else None
        if isinstance(code, str) and re.fullmatch(r"[A-Z0-9_-]{1,32}", code):
            return {"error": f"scanner reported {code} (exit {result.returncode})"}
        return {"error": f"scanner reported errors (exit {result.returncode})"}
    if result.returncode != 0 and result.returncode != finding_exit:
        return {"error": f"scanner exited with code {result.returncode}"}

    try:
        if (
            parse_findings is gitleaks_findings
            and data is not None
            and not isinstance(data, list)
        ):
            raise ValueError("expected a JSON array")
        if parse_findings is semgrep_findings and not isinstance(data["results"], list):
            raise ValueError("expected a results array")
        findings = parse_findings(data)
        if any(finding["severity"] not in SEVERITIES for finding in findings):
            raise ValueError("unrecognized severity")
        if result.returncode != 0 and not findings:
            raise ValueError("missing findings for nonzero exit")
    except (KeyError, TypeError, ValueError, AttributeError):
        return {"error": f"unexpected report format (exit {result.returncode})"}
    return {"findings": findings}


def markdown_cell(value):
    return re.sub(r"([\\|*_`\[\]()!~])", r"\\\1", escape(" ".join(str(value).split())))


def render_report(results):
    header = [
        "# 独立代码扫描",
        "",
        "| 扫描器 | 状态 | Critical | High | Medium | Low | Info |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    details = []
    for name, result in results.items():
        if error := result.get("error"):
            header.append(f"| {name} | 失败（{error}） | — | — | — | — | — |")
            continue
        if "skipped" in result:
            header.append(f"| {name} | 不适用 | — | — | — | — | — |")
            continue
        findings = result["findings"]
        counts = Counter(item["severity"] for item in findings)
        header.append(
            f"| {name} | 完成 | "
            + " | ".join(str(counts[s]) for s in SEVERITIES)
            + " |"
        )
        if findings:
            details.extend(
                [
                    "",
                    f"## {name}",
                    "",
                    "| 级别 | 位置或依赖 | 规则或版本范围 | 说明 |",
                    "| --- | --- | --- | --- |",
                ]
            )
        for item in sorted(
            findings, key=lambda entry: SEVERITIES.index(entry["severity"])
        ):
            if "package" in item:
                description = " / ".join(
                    entry.get("title", entry.get("package")) for entry in item["via"]
                )
                row = (item["severity"], item["package"], item["range"], description)
            else:
                row = (
                    item["severity"],
                    f'{item["path"]}:{item["line"]}',
                    item["rule"],
                    item.get("commit", item.get("message", "")),
                )
            details.append(
                "| " + " | ".join(markdown_cell(value) for value in row) + " |"
            )
    return "\n".join(header) + "\n", "\n".join(details) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    results = {
        "Semgrep CE": run_scanner(
            [
                "semgrep",
                "scan",
                "--config",
                str(RULES),
                "--metrics=off",
                "--disable-version-check",
                "--strict",
                "--json",
                "--no-rewrite-rule-ids",
                "src",
            ],
            semgrep_findings,
        ),
        "Gitleaks": run_scanner(
            [
                "gitleaks",
                "git",
                "--log-opts=HEAD",
                "--no-banner",
                "--redact=100",
                "--exit-code=10",
                "--report-format=json",
                "--report-path=-",
                ".",
            ],
            gitleaks_findings,
            finding_exit=10,
        ),
        "npm audit": run_scanner(
            [
                "npm",
                "audit",
                "--json",
                "--package-lock-only",
                "--ignore-scripts",
                "--include=dev",
                "--include=optional",
                "--include=peer",
                "--audit-level=low",
                "--registry=https://registry.npmjs.org",
            ],
            npm_findings,
            finding_exit=1,
        ),
        "pip-audit": {"skipped": "react-game has no Python dependencies"},
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary, details = render_report(results)
    (args.output_dir / "report.md").write_text(summary + details, encoding="utf-8")
    (args.output_dir / "findings.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(summary, end="")
    if summary_path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary_path).open("a", encoding="utf-8") as stream:
            stream.write(summary + "\n详细报告见产物 `independent-code-scan`。\n")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        # Annotate current source only. Historical Git line numbers refer to old commits.
        for item in results["Semgrep CE"].get("findings", [])[:10]:
            if not re.fullmatch(r"src/[\w./-]+", item["path"]) or not isinstance(
                item["line"], int
            ):
                continue
            level = "error" if item["severity"] in BLOCKING else "warning"
            print(
                f'::{level} file={item["path"]},line={item["line"]}::Semgrep finding. See scan report.'
            )

    if any("error" in result for result in results.values()):
        return 2
    return int(
        any(
            item["severity"] in BLOCKING
            for result in results.values()
            for item in result.get("findings", [])
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
