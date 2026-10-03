import json
import os
import sqlite3
import urllib.request

from flask import Flask, Response, abort, flash, g, redirect, render_template, request

from scanner import coverage, detect, scan, score


BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "codesentry.db")


SAMPLE = '''import os, pickle, hashlib, sqlite3, subprocess
from flask import Flask, request

app = Flask(__name__)

# Example only: never hardcode real API keys in source code.
API_KEY = os.environ.get("STRIPE_API_KEY", "your-stripe-api-key-here")

@app.route("/user")
def user():
    name = request.args.get("name")
    db = sqlite3.connect("app.db")
    row = db.execute(
        "SELECT * FROM users WHERE name = ?",
        (name,)
    ).fetchone()
    return str(row)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output(
        "ping -c 1 " + host,
        shell=True
    )


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))


def hash_password(p):
    return hashlib.md5(p.encode()).hexdigest()


if __name__ == "__main__":
    app.run(debug=True)
'''


app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "dev-only-change-me"
)

app.config["MAX_CONTENT_LENGTH"] = 300_000


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row

    return g.db


@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)

    if conn:
        conn.close()


def init_db():
    with sqlite3.connect(DB) as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS scans(
                id INTEGER PRIMARY KEY,
                name TEXT,
                lang TEXT,
                code TEXT,
                score INTEGER,
                grade TEXT,
                findings TEXT,
                note TEXT,
                ai TEXT,
                created TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


@app.route("/")
def index():
    return render_template(
        "index.html",
        sample=SAMPLE,
        rules=coverage()
    )


@app.route("/vulnerabilities")
def vulnerabilities():
    return render_template(
        "coverage.html",
        rules=coverage()
    )


@app.route("/about")
def about():
    return render_template(
        "about.html",
        n=len(coverage())
    )


@app.post("/scan")
def do_scan():

    code = request.form.get("code", "")

    if not code.strip():
        flash("Paste some code or upload a file first.")
        return redirect("/")

    if len(code) > 200_000:
        flash("That file is too large. The limit is 200 KB.")
        return redirect("/")

    lang = request.form.get("lang", "auto")

    if lang == "auto":
        lang = detect(code)

    findings, note = scan(code, lang)

    s, grade = score(findings)

    cur = db().execute(
        """
        INSERT INTO scans(
            name,
            lang,
            code,
            score,
            grade,
            findings,
            note
        )
        VALUES(?,?,?,?,?,?,?)
        """,
        (
            request.form.get("name", "").strip()[:60]
            or "Pasted code",
            lang,
            code,
            s,
            grade,
            json.dumps(findings),
            note
        )
    )

    db().commit()

    return redirect(
        f"/report/{cur.lastrowid}"
    )


def load(sid):

    r = db().execute(
        "SELECT * FROM scans WHERE id=?",
        (sid,)
    ).fetchone()

    if not r:
        abort(404)

    return r, json.loads(r["findings"])


@app.route("/report/<int:sid>")
def report(sid):

    r, findings = load(sid)

    counts = {
        k: sum(
            f["sev"] == k
            for f in findings
        )
        for k in (
            "Critical",
            "High",
            "Medium",
            "Low"
        )
    }

    rank = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3
    }

    heat = {}

    for f in findings:

        if (
            f["line"] not in heat
            or rank[f["sev"]] < rank[heat[f["line"]]]
        ):
            heat[f["line"]] = f["sev"]

    return render_template(
        "report.html",
        r=r,
        findings=findings,
        counts=counts,
        heat=heat,
        lines=r["code"].splitlines(),
        ai_enabled=bool(
            os.environ.get("ANTHROPIC_API_KEY")
        )
    )


@app.route("/report/<int:sid>.json")
def report_json(sid):

    r, findings = load(sid)

    body = json.dumps(
        {
            "name": r["name"],
            "language": r["lang"],
            "score": r["score"],
            "grade": r["grade"],
            "scanned": r["created"],
            "findings": findings
        },
        indent=2
    )

    return Response(
        body,
        mimetype="application/json",
        headers={
            "Content-Disposition":
                f"attachment; filename="
                f"codesentry_report_{sid}.json"
        }
    )


@app.post("/report/<int:sid>/ai")
def ai_review(sid):

    r, findings = load(sid)

    key = os.environ.get(
        "ANTHROPIC_API_KEY"
    )

    if not key:

        flash(
            "Set the ANTHROPIC_API_KEY "
            "environment variable to enable AI review."
        )

        return redirect(
            f"/report/{sid}"
        )

    prompt = (
        "You are a senior application security reviewer. "
        "Review this "
        + r["lang"]
        + " code. "
        "Static analysis already found: "
        + json.dumps(
            [
                (f["title"], f["line"])
                for f in findings
            ]
        )
        + ". Give: "
        "1) the 3 most important risks in plain language, "
        "2) any issues the scanner missed "
        "(auth, logic, validation), "
        "3) one corrected code snippet "
        "for the worst issue. "
        "Be concise.\n\n"
        + r["code"][:12000]
    )

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        method="POST",
        data=json.dumps(
            {
                "model": os.environ.get(
                    "AI_MODEL",
                    "claude-sonnet-5-5"
                ),
                "max_tokens": 1200,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            }
        ).encode(),
        headers={
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
    )

    try:

        with urllib.request.urlopen(
            req,
            timeout=60
        ) as resp:

            response_data = json.load(resp)

            text = "".join(
                item.get("text", "")
                for item in response_data["content"]
            )

        db().execute(
            "UPDATE scans SET ai=? WHERE id=?",
            (text, sid)
        )

        db().commit()

    except Exception as e:

        flash(
            f"AI review failed: {e}"
        )

    return redirect(
        f"/report/{sid}#ai"
    )


@app.route("/history")
def history():

    rows = db().execute(
        """
        SELECT
            id,
            name,
            lang,
            score,
            grade,
            findings,
            created
        FROM scans
        ORDER BY id DESC
        LIMIT 100
        """
    ).fetchall()

    formatted_rows = []

    for r in rows:

        formatted_rows.append(
            dict(
                r,
                n=len(
                    json.loads(
                        r["findings"]
                    )
                )
            )
        )

    return render_template(
        "history.html",
        rows=formatted_rows
    )


@app.post("/report/<int:sid>/delete")
def delete(sid):

    db().execute(
        "DELETE FROM scans WHERE id=?",
        (sid,)
    )

    db().commit()

    return redirect("/history")


init_db()


if __name__ == "__main__":
    app.run(
        debug=False
    )
