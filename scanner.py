"""Static analysis engine: Python AST checks + regex rules for JS/PHP and secrets. Never executes code."""
import ast, re

META = {  # id: (title, severity, CWE, OWASP, why it matters, how to fix)
 "SQLI": ("SQL injection", "Critical", "CWE-89", "A03 Injection",
  "User input is concatenated into a SQL query, so an attacker can change the query and read or destroy data.",
  "Use parameterised queries: cursor.execute('SELECT * FROM users WHERE name = ?', (name,))"),
 "CMDI": ("OS command injection", "High", "CWE-78", "A03 Injection",
  "A shell command is built from dynamic input. An attacker can append their own commands.",
  "Avoid the shell. Pass a list: subprocess.run(['ping', '-c', '1', host]) and validate host."),
 "EVAL": ("Dynamic code execution", "Critical", "CWE-95", "A03 Injection",
  "eval/exec runs arbitrary code. If any part of the input is attacker-controlled, they control your server.",
  "Remove eval/exec. Use ast.literal_eval or json.loads for data, and explicit logic for behaviour."),
 "DESER": ("Insecure deserialization", "High", "CWE-502", "A08 Integrity Failures",
  "Loading pickle/marshal data from an untrusted source can execute arbitrary code.",
  "Use JSON for untrusted data. Never unpickle data you did not create and sign."),
 "YAML": ("Unsafe YAML load", "High", "CWE-502", "A08 Integrity Failures",
  "yaml.load without a safe Loader can construct arbitrary Python objects.", "Use yaml.safe_load(data)."),
 "WEAKHASH": ("Weak hash algorithm", "Medium", "CWE-327", "A02 Cryptographic Failures",
  "MD5 and SHA-1 are broken and fast to brute-force, which is unsafe for passwords.",
  "Hash passwords with bcrypt, argon2 or werkzeug.security.generate_password_hash. Use SHA-256+ for integrity."),
 "TLS": ("TLS verification disabled", "Medium", "CWE-295", "A02 Cryptographic Failures",
  "verify=False allows man-in-the-middle attacks on the connection.", "Remove verify=False and fix the certificate instead."),
 "DEBUG": ("Debug mode enabled", "Medium", "CWE-489", "A05 Misconfiguration",
  "Debug mode can expose an interactive console and stack traces in production.",
  "Read it from the environment and default to False: debug=os.environ.get('DEBUG') == '1'."),
 "SECRET": ("Hardcoded secret", "High", "CWE-798", "A07 Auth Failures",
  "Credentials in source code leak through Git history, logs and screenshots.",
  "Load secrets from environment variables or a secrets manager, and rotate this one."),
 "AWS": ("AWS access key in code", "Critical", "CWE-798", "A07 Auth Failures",
  "A cloud key is exposed. Bots scan public repos for these within minutes.", "Revoke the key now, then use IAM roles or env vars."),
 "PRIVKEY": ("Private key in code", "Critical", "CWE-321", "A02 Cryptographic Failures",
  "A private key committed to source is compromised.", "Remove it, regenerate the key pair and load keys from secure storage."),
 "XSS": ("Cross-site scripting (XSS)", "High", "CWE-79", "A03 Injection",
  "Untrusted data is written to the page as HTML, letting attackers run scripts in other users' browsers.",
  "Use textContent instead of innerHTML, or escape output (htmlspecialchars in PHP)."),
 "LFI": ("File inclusion", "Critical", "CWE-98", "A03 Injection",
  "A file path comes from user input, which can expose server files or run attacker code.", "Use a fixed allow-list of files; never include user-supplied paths."),
 "WEAKRAND": ("Predictable randomness", "Low", "CWE-338", "A02 Cryptographic Failures",
  "Math.random() is not cryptographically secure, so tokens made with it can be guessed.", "Use crypto.getRandomValues() or crypto.randomBytes()."),
}
RX = [
 ("SECRET", "*", r"(?i)(password|passwd|pwd|secret|api[_-]?key|token)\w*['\"]?\s*[:=]\s*['\"][^'\"\s]{6,}['\"]"),
 ("AWS", "*", r"AKIA[0-9A-Z]{16}"),
 ("PRIVKEY", "*", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
 ("XSS", "javascript", r"\.innerHTML\s*=|document\.write\("),
 ("EVAL", "javascript php", r"\beval\s*\("),
 ("SQLI", "javascript php", r"(?i)(select|insert|update|delete)\b.*['\"]\s*(\+|\.)\s*\$?\w+|(query|execute)\s*\(.*\$_(GET|POST|REQUEST)"),
 ("XSS", "php", r"echo\s+.*\$_(GET|POST|REQUEST)"),
 ("LFI", "php", r"(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST)"),
 ("CMDI", "php", r"\b(system|exec|shell_exec|passthru)\s*\(.*\$_(GET|POST|REQUEST)"),
 ("WEAKHASH", "javascript php", r"\b(md5|sha1)\s*\(|createHash\(['\"](md5|sha1)['\"]\)"),
 ("WEAKRAND", "javascript", r"Math\.random\(\)"),
]


def detect(code):
    if "<?php" in code or re.search(r"\$_(GET|POST)", code):
        return "php"
    if re.search(r"^\s*def \w+\(.*\):|^\s*import \w+(, *\w+)*\s*$|^from \w+ import", code, re.M):
        return "python"
    if re.search(r"\b(const|let|var|function)\b|=>|document\.|require\(", code):
        return "javascript"
    return "other"


def dotted(n):
    parts = []
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
    return ".".join(reversed(parts))


def dynamic(a):
    return isinstance(a, (ast.JoinedStr, ast.BinOp)) or (isinstance(a, ast.Call) and dotted(a.func).endswith(".format"))


def is_const(node, value):
    return isinstance(node, ast.Constant) and node.value is value


class PyScan(ast.NodeVisitor):
    def __init__(self):
        self.found = []

    def visit_Call(self, n):
        f, kw = dotted(n.func), {k.arg: k.value for k in n.keywords}
        last = f.split(".")[-1]
        hit = None
        if f in ("eval", "exec"): hit = "EVAL"
        elif f in ("os.system", "os.popen") or (f.startswith("subprocess.") and is_const(kw.get("shell"), True)): hit = "CMDI"
        elif f in ("pickle.load", "pickle.loads", "marshal.loads", "cPickle.loads"): hit = "DESER"
        elif f == "yaml.load" and "Loader" not in kw: hit = "YAML"
        elif f in ("hashlib.md5", "hashlib.sha1"): hit = "WEAKHASH"
        elif f.startswith("requests.") and is_const(kw.get("verify"), False): hit = "TLS"
        elif last == "run" and is_const(kw.get("debug"), True): hit = "DEBUG"
        elif last in ("execute", "executemany", "executescript") and n.args and dynamic(n.args[0]): hit = "SQLI"
        if hit:
            self.found.append((hit, n.lineno))
        self.generic_visit(n)


def scan(code, lang):
    lines, seen, out = code.splitlines(), set(), []

    def add(rid, ln):
        if (rid, ln) in seen or not 1 <= ln <= len(lines):
            return
        seen.add((rid, ln))
        t, sev, cwe, owasp, why, fix = META[rid]
        out.append(dict(id=rid, title=t, sev=sev, cwe=cwe, owasp=owasp, why=why, fix=fix,
                        line=ln, snippet=lines[ln - 1].strip()[:160]))

    note = None
    if lang == "python":
        try:
            v = PyScan()
            v.visit(ast.parse(code))
            for rid, ln in v.found:
                add(rid, ln)
        except SyntaxError as e:
            note = f"Python syntax error on line {e.lineno}; AST checks were skipped, pattern checks still ran."
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith(("#", "//", "*", "/*")) or "environ" in line or "getenv" in line:
            continue
        for rid, langs, pat in RX:
            if (langs == "*" or lang in langs.split()) and re.search(pat, line):
                add(rid, i)
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    out.sort(key=lambda f: (order[f["sev"]], f["line"]))
    return out, note


def score(findings):
    w = {"Critical": 25, "High": 15, "Medium": 7, "Low": 3}
    s = max(0, 100 - sum(w[f["sev"]] for f in findings))
    return s, "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"


PY_IDS = {"SQLI", "CMDI", "EVAL", "DESER", "YAML", "WEAKHASH", "TLS", "DEBUG"}


def coverage():
    """Every detection rule with the languages it applies to (used by the Coverage page and header menu)."""
    names = {"python": "Python", "javascript": "JavaScript", "php": "PHP"}
    langs = {k: set() for k in META}
    for k in PY_IDS:
        langs[k].add("Python")
    for rid, l, _ in RX:
        langs[rid].update(["All languages"] if l == "*" else [names[x] for x in l.split()])
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    rules = [dict(id=k, title=v[0], sev=v[1], cwe=v[2], owasp=v[3], why=v[4], fix=v[5], langs=sorted(langs[k]))
             for k, v in META.items()]
    return sorted(rules, key=lambda r: (order[r["sev"]], r["title"]))
