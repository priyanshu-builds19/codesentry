# CodeSentry: Code Review & Vulnerability Scanner

Paste or upload source code and get a security report: score and grade, every issue with severity, line number, CWE/OWASP reference and a concrete fix, plus a source viewer with the vulnerable lines highlighted.

**Stack:** Python, Flask, SQLite, vanilla JS. No external services required.

## Vulnerabilities detected
| Severity | Issue | CWE |
|---|---|---|
| Critical | SQL injection, dynamic code execution (eval/exec), file inclusion, AWS keys and private keys in code | CWE-89, 95, 98, 798, 321 |
| High | OS command injection, insecure deserialization (pickle, YAML), XSS, hardcoded secrets | CWE-78, 502, 79, 798 |
| Medium | Weak hashes (MD5/SHA-1), disabled TLS verification, debug mode enabled | CWE-327, 295, 489 |
| Low | Predictable randomness (Math.random) | CWE-338 |

The app also has a **Vulnerabilities** page (every rule with explanation and fix) and an **About** page.

## How it works
- **Python AST analysis** (`ast` module) finds SQL injection, command injection, `eval/exec`, unsafe `pickle`/`yaml.load`, weak hashes, disabled TLS verification and debug mode, by inspecting real syntax rather than text.
- **Pattern rules** cover JavaScript and PHP (XSS, file inclusion, SQL concatenation) and secrets in any language (hardcoded passwords, AWS keys, private keys).
- **Scoring:** 100 minus weighted penalties (Critical 25, High 15, Medium 7, Low 3), mapped to grades A to F.
- **Optional AI review:** set `ANTHROPIC_API_KEY` to get a model's second opinion on logic and auth flaws the rules cannot see (`AI_MODEL` overrides the model).
- Uploaded code is **read, never executed**. Size limit 200 KB.

## Run
```bash
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000 and click "Load vulnerable example".

## Limitations
Static analysis has false positives and misses logic bugs; use it as a first-pass review. Rules are in `scanner.py` and easy to extend.

## Ideas
GitHub repo URL scanning, SARIF export, more languages, CI integration.
