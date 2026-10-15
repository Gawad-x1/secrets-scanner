#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Secrets Scanner v2 - فاحص أسرار متطور (بدون مكتبات خارجية، Python 3.8+)

الهدف: يلاقي المفاتيح/الباسوردات/التوكنز اللي اتسربت في الكود أو في تاريخ الـ commits.

أمثلة:
  python secrets_scanner.py .                                  # فحص فولدر (بيحترم .gitignore)
  python secrets_scanner.py . --history                        # + تاريخ الـ commits
  python secrets_scanner.py https://github.com/user/repo --history --html report.html
  python secrets_scanner.py user/repo --history                # اختصار لريبو جيت هاب
  python secrets_scanner.py --user Gawad-x1 --history          # كل ريبوهات يوزر
  python secrets_scanner.py . --staged --fail-on high          # للـ pre-commit
  python secrets_scanner.py . --install-hook                   # يركّب pre-commit hook
  python secrets_scanner.py . --history --sarif r.sarif --json r.json --html r.html
  python secrets_scanner.py . --history --gen-replace secrets.txt   # ملف لـ git filter-repo

للريبوهات الخاصة / رفع حد الـ API: حط GITHUB_TOKEN في متغيرات البيئة.
لتجاهل سطر: ضيف  secrets-scanner:ignore  في نفس السطر.
لتجاهل ملفات: اعمل ملف .secretsignore (glob لكل سطر).
"""
import argparse, base64, concurrent.futures as cf, fnmatch, hashlib, html, json, math, os, re
import shutil, stat, subprocess, sys, tempfile, urllib.error, urllib.request
from collections import Counter
from datetime import datetime

VERSION = "2.0"
SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
SEV_AR = {"high": "عالية", "medium": "متوسطة", "low": "منخفضة", "info": "معلومة"}
SEV_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "⚪"}
WEIGHT = {"high": 25, "medium": 10, "low": 3, "info": 0}

# (الاسم, regex, الخطورة, نصيحة الإصلاح)
RULES = [
    ("AWS Access Key ID", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b", "high", "ألغِ المفتاح من IAM وولّد واحد جديد، وراجع CloudTrail لأي استخدام مشبوه."),
    ("AWS Secret Key", r"(?i)aws.{0,20}(?:secret|key).{0,5}['\"=:\s]+([A-Za-z0-9/+=]{40})\b", "high", "ألغِ المفتاح من IAM."),
    ("Google API Key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "high", "قيّد المفتاح (HTTP referrers / APIs) أو احذفه من Google Cloud Console."),
    ("Google OAuth Client Secret", r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b", "high", "اعمل reset للـ secret من Google Cloud Console."),
    ("Firebase Server Key", r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,}\b", "high", "جدد المفتاح من Firebase Console."),
    ("Stripe Live Secret", r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b", "high", "اعمل roll للمفتاح من Stripe Dashboard فوراً."),
    ("Stripe Test Secret", r"\bsk_test_[0-9a-zA-Z]{24,}\b", "low", "مفتاح تجريبي، الأفضل تنقله لـ env."),
    ("GitHub Token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b", "high", "ألغِ التوكن من GitHub > Settings > Developer settings."),
    ("GitHub Fine-grained Token", r"\bgithub_pat_[A-Za-z0-9_]{50,}\b", "high", "ألغِ التوكن من GitHub Settings."),
    ("GitLab Token", r"\bglpat-[A-Za-z0-9_\-]{20}\b", "high", "ألغِ التوكن من GitLab."),
    ("Telegram Bot Token", r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b", "high", "اعمل /revoke من BotFather وخد توكن جديد."),
    ("Discord Bot Token", r"\b[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27,}\b", "high", "اعمل Reset Token من Discord Developer Portal."),
    ("Slack Token", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b", "high", "ألغِ التوكن من Slack API."),
    ("OpenAI API Key", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}\b", "high", "احذف المفتاح من platform.openai.com وولّد واحد جديد."),
    ("Anthropic API Key", r"\bsk-ant-[A-Za-z0-9_\-]{40,}\b", "high", "ألغِ المفتاح من Anthropic Console."),
    ("Hugging Face Token", r"\bhf_[A-Za-z0-9]{34}\b", "high", "ألغِ التوكن من Hugging Face Settings."),
    ("SendGrid API Key", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", "high", "ألغِ المفتاح من SendGrid."),
    ("Twilio API Key", r"\bSK[0-9a-f]{32}\b", "medium", "ألغِ المفتاح من Twilio Console."),
    ("Mailgun API Key", r"\bkey-[0-9a-f]{32}\b", "medium", "جدد المفتاح من Mailgun."),
    ("NPM Token", r"\bnpm_[A-Za-z0-9]{36}\b", "high", "ألغِ التوكن من npmjs.com."),
    ("Supabase Access Token", r"\bsbp_[0-9a-f]{40}\b", "high", "ألغِ التوكن من Supabase Dashboard."),
    ("Supabase Secret Key", r"\bsb_secret_[A-Za-z0-9_\-]{20,}\b", "high", "جدد المفتاح من Supabase."),
    ("Azure Storage Key", r"AccountKey=[A-Za-z0-9+/=]{86,90}", "high", "اعمل regenerate للمفتاح من Azure Portal."),
    ("JWT", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "medium", "راجع الـ JWT ده: لو بيحتوي صلاحيات حساسة جدده."),
    ("Private Key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", "high", "اعتبر المفتاح مكشوف: ولّد زوج جديد وبدّله في كل مكان."),
    ("Database URL with password", r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://([^\s:@/'\"]+):([^\s:@/'\"]+)@([^\s/'\"]+)", "high", "غيّر باسورد الداتابيز وخليه في env."),
    ("Credentials in URL", r"\bhttps?://[^\s:@/'\"]{2,}:[^\s:@/'\"]{4,}@[\w.\-]+", "medium", "شيل الباسورد من اللينك واستخدم متغير بيئة."),
    ("Generic secret assignment", r"(?i)\b(?:api[_-]?key|secret|passw(?:or)?d|token|auth|private[_-]?key)[A-Za-z0-9_]*\s*[:=]\s*['\"]([^'\"\s]{12,})['\"]", "medium", "انقل القيمة لمتغير بيئة (env)."),
]
COMPILED = [(n, re.compile(p), s, f) for n, p, s, f in RULES]

# ملفات حساسة بالاسم
SENSITIVE_FILES = [
    (re.compile(r"(^|/)\.env(\.(?!example$|sample$|template$|dist$)[\w.\-]+)?$"), "ملف .env", "high", "شيل الملف من git، حطه في .gitignore، وغيّر كل الأسرار اللي فيه."),
    (re.compile(r"(^|/)id_(rsa|dsa|ecdsa|ed25519)$"), "SSH private key file", "high", "ولّد مفتاح SSH جديد وشيل القديم من السيرفرات."),
    (re.compile(r"\.(p12|pfx|jks|keystore)$", re.I), "Keystore file", "high", "غيّر الـ keystore والباسورد بتاعه."),
    (re.compile(r"\.(pem|key)$", re.I), "Key/Cert file", "medium", "تأكد إن الملف مش مفتاح خاص."),
    (re.compile(r"(^|/)(credentials\.json|service[-_]?account[\w\-]*\.json|\.htpasswd|\.netrc|\.pypirc|terraform\.tfstate(\.backup)?)$"), "Credentials file", "high", "شيل الملف من git وغيّر كل الأسرار اللي فيه."),
    (re.compile(r"(^|/)\.npmrc$"), "npmrc (ممكن فيه auth token)", "low", "راجع الملف ومتحطش فيه توكن."),
]

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", ".idea", ".vscode", "vendor"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip", ".gz", ".tar", ".mp4", ".mp3", ".mov",
            ".woff", ".woff2", ".ttf", ".eot", ".otf", ".lock", ".exe", ".dll", ".so", ".pyc", ".map", ".jar", ".class"}
PLACEHOLDERS = ("example", "your_", "your-", "yourkey", "xxxx", "changeme", "placeholder", "<", "${", "{{",
                "process.env", "os.environ", "getenv", "dummy", "sample", "fake", "test_key", "todo")
WEAK_PW = {"password", "pass", "passwd", "changeme", "postgres", "root", "user", "admin", "secret", "example", "123456", "mypassword"}
MAX_FILE = 1_500_000
IGNORE_MARK = "secrets-scanner:ignore"
KEY_HINT = re.compile(r"key|secret|token|passw|pwd|auth|cred|private|bearer|api")
SRI_RE = re.compile(r"^sha(256|384|512)[-=]")


# ───────────────────────── أدوات مساعدة ─────────────────────────
def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def redact(s):
    s = s.strip()
    return s if len(s) <= 8 else s[:4] + "*" * min(len(s) - 8, 12) + s[-4:]


def fingerprint(kind, raw):
    return hashlib.sha256((kind + "\0" + raw).encode("utf-8", "replace")).hexdigest()[:16]


def jwt_role(tok):
    try:
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p)).get("role")
    except Exception:
        return None


def skip_ext(path):
    return os.path.splitext(path)[1].lower() in SKIP_EXT or path.endswith(".min.js")


def mk(kind, raw, sev, fix, file, line=None, commit=None, author=None, date=None, source="working"):
    return dict(type=kind, severity=sev, file=file, line=line, commit=commit, author=author, date=date,
                secret=redact(raw), fix=fix, fp=fingerprint(kind, raw), source=source, _raw=raw)


def scan_line(line):
    """يرجع قايمة (النوع, القيمة, الخطورة, الإصلاح) لسطر واحد."""
    if len(line) > 3000 or IGNORE_MARK in line:
        return []
    hits = []
    low = line.lower()
    for name, rx, sev, fix in COMPILED:
        m = rx.search(line)
        if not m:
            continue
        val = m.group(0)
        if name == "Database URL with password":
            pw, host = m.group(2), m.group(3).split(":")[0].lower()
            if pw.lower() in WEAK_PW or pw[0] in "${<%" or "example" in host:
                continue
            if host in ("localhost", "127.0.0.1", "db", "postgres", "mysql", "redis", "mongo"):
                sev = "low"
        elif name == "Generic secret assignment":
            val = m.group(1)
            if any(p in val.lower() or p in low for p in PLACEHOLDERS) or entropy(val) < 3.0:
                continue
        elif name == "JWT":
            role = jwt_role(val)
            if role == "service_role":
                name, sev, fix = "Supabase service_role JWT", "high", "خطير جداً: جدد الـ JWT secret من Supabase فوراً."
            elif role == "anon":
                continue  # anon key معمول يبان للعامة
        elif name == "Credentials in URL":
            if any(p in low for p in PLACEHOLDERS):
                continue
        if "EXAMPLE" in val.upper() and name.startswith("AWS"):
            continue
        hits.append((name, val, sev, fix))
    if any(h[0] != "Generic secret assignment" for h in hits):
        hits = [h for h in hits if h[0] != "Generic secret assignment"]
    if not hits:
        # entropy العالي لوحده بيجيب إنذارات غلط (checksums, SRI hashes)، فلازم السطر يكون فيه اسم يوحي بسر
        if not KEY_HINT.search(low):
            return hits
        for tok in re.findall(r"['\"]([A-Za-z0-9+/_\-=]{32,})['\"]", line):
            if SRI_RE.match(tok):
                continue
            if entropy(tok) >= 4.5 and not any(p in low for p in PLACEHOLDERS):
                hits.append(("High-entropy string", tok, "low", "راجع: لو ده سر انقله لـ env."))
                break
    return hits


def filename_hits(path):
    base = path.replace("\\", "/")
    for rx, label, sev, fix in SENSITIVE_FILES:
        if rx.search(base):
            return [(label, base, sev, fix)]
    return []


def load_ignore(path):
    pats = []
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8", errors="ignore") as f:
            pats = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    return pats


def ignored(path, pats):
    p = path.replace("\\", "/")
    return any(fnmatch.fnmatch(p, g) or fnmatch.fnmatch(os.path.basename(p), g) for g in pats)


# ───────────────────────── الفحص ─────────────────────────
def list_files(root, all_files=False):
    if not all_files and os.path.isdir(os.path.join(root, ".git")):
        try:
            out = subprocess.run(["git", "-C", root, "ls-files", "-co", "--exclude-standard", "-z"],
                                 capture_output=True, check=True).stdout
            return [p for p in out.decode("utf-8", "replace").split("\0") if p]
        except Exception:
            pass
    res = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            res.append(os.path.relpath(os.path.join(dp, fn), root).replace("\\", "/"))
    return res


def scan_file(root, rel, pats):
    if ignored(rel, pats) or any(part in SKIP_DIRS for part in rel.split("/")[:-1]):
        return []
    out = []
    for name, raw, sev, fix in filename_hits(rel):
        out.append(mk(name, raw, sev, fix, rel))
    if skip_ext(rel):
        return out
    path = os.path.join(root, rel)
    try:
        if os.path.getsize(path) > MAX_FILE:
            return out
        with open(path, "r", encoding="utf-8", errors="strict") as f:
            for i, line in enumerate(f, 1):
                for name, val, sev, fix in scan_line(line):
                    out.append(mk(name, val, sev, fix, rel, i))
    except (UnicodeDecodeError, OSError):
        pass
    return out


def parse_patch(stream, pats, source):
    """بيحلل خرج git log -p أو git diff ويرجع النتايج من الأسطر المضافة بس."""
    out, commit, author, date, file, lineno, skip = [], None, None, None, None, 0, False
    for raw in stream:
        raw = raw.rstrip("\n")
        if raw.startswith("@@COMMIT "):
            parts = raw[9:].split("\x1f")
            commit = parts[0][:8]
            author = parts[1] if len(parts) > 1 else None
            date = parts[2] if len(parts) > 2 else None
            file = None
        elif raw.startswith("+++ "):
            file = raw[6:] if raw.startswith("+++ b/") else None
            skip = bool(file) and (ignored(file, pats) or any(p in SKIP_DIRS for p in file.split("/")[:-1]))
            if file and not skip:
                for name, rawv, sev, fix in filename_hits(file):
                    out.append(mk(name, rawv, sev, fix, file, None, commit, author, date, source))
            if file and skip_ext(file):
                skip = True
        elif raw.startswith("@@ "):
            m = re.search(r"\+(\d+)", raw)
            lineno = int(m.group(1)) - 1 if m else 0
        elif raw.startswith("+"):
            lineno += 1
            if file and not skip:
                for name, val, sev, fix in scan_line(raw[1:]):
                    out.append(mk(name, val, sev, fix, file, lineno, commit, author, date, source))
        elif raw.startswith(" "):
            lineno += 1
    return out


def run_git_stream(args_list):
    try:
        return subprocess.Popen(["git"] + args_list, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        sys.exit("git مش متسطب أو مش في الـ PATH")


def scan_history(root, pats):
    p = run_git_stream(["-C", root, "log", "--all", "-p", "--no-color", "--date=short",
                        "--format=@@COMMIT %H%x1f%an%x1f%ad"])
    res = parse_patch(p.stdout, pats, "history")
    p.wait()
    return res


def scan_staged(root, pats):
    p = run_git_stream(["-C", root, "diff", "--cached", "-U0", "--no-color"])
    res = parse_patch(p.stdout, pats, "staged")
    p.wait()
    return res


def merge(working, history):
    """الأسرار الموجودة حالياً = active. اللي اتمسحت بس لسه في التاريخ = history."""
    res, wfp = {}, {f["fp"] for f in working}
    for f in working:
        f["status"] = "active"
        res.setdefault((f["fp"], f["file"]), f)
    old = {}
    for f in history:  # git log من الأحدث للأقدم، فآخر واحد بيفضل = أقدم commit
        if f["fp"] in wfp:
            continue
        f["status"] = "history"
        old[(f["fp"], f["file"])] = f
    res.update(old)
    out = list(res.values())
    out.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["status"] != "active", f["file"], f["line"] or 0))
    return out


def scan_path(root, a, label, pats):
    files = list_files(root, a.all_files)
    working = []
    with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
        for r in ex.map(lambda p: scan_file(root, p, pats), files):
            working += r
    hist = scan_history(root, pats) if a.history else []
    res = merge(working, hist)
    for f in res:
        f["repo"] = label
    return res


# ───────────────────────── ريموت (clone / يوزر) ─────────────────────────
def is_remote(t):
    return bool(re.match(r"^(https?://|git@|ssh://|file://)", t)) or \
        (not os.path.exists(t) and re.match(r"^[\w.\-]+/[\w.\-]+$", t) is not None)


def to_url(t):
    return f"https://github.com/{t}.git" if re.match(r"^[\w.\-]+/[\w.\-]+$", t) else t


def _rm(func, path, exc):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


def clone(url, token):
    tmp = tempfile.mkdtemp(prefix="secscan_")
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    if token and "github.com" in url:
        b = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.extraHeader",
                   GIT_CONFIG_VALUE_0=f"Authorization: Basic {b}")
    dest = os.path.join(tmp, "repo")
    r = subprocess.run(["git", "clone", "--quiet", "--no-tags", url, dest], env=env, capture_output=True, text=True)
    if r.returncode:
        shutil.rmtree(tmp, onerror=_rm)
        raise RuntimeError((r.stderr or "clone فشل").strip()[-300:])
    return tmp, dest


def list_user_repos(user, token, forks):
    repos, page = [], 1
    while True:
        h = {"Accept": "application/vnd.github+json", "User-Agent": "secrets-scanner"}
        if token:
            h["Authorization"] = "Bearer " + token
        try:
            req = urllib.request.Request(f"https://api.github.com/users/{user}/repos?per_page=100&page={page}", headers=h)
            data = json.load(urllib.request.urlopen(req, timeout=30))
        except urllib.error.HTTPError as e:
            sys.exit("اليوزر مش موجود." if e.code == 404 else f"GitHub API رجع {e.code} (جرب GITHUB_TOKEN).")
        if not data:
            break
        repos += [r["clone_url"] for r in data if forks or not r.get("fork")]
        page += 1
    return repos


# ───────────────────────── التقارير ─────────────────────────
def score(findings):
    return max(0, 100 - sum(WEIGHT[f["severity"]] for f in findings))


def status_txt(f):
    return "موجود في الكود الحالي" if f["status"] == "active" else (
        "في commit جديد (staged)" if f["status"] == "staged" else "اتمسح من الكود بس لسه في تاريخ git")


def print_text(findings):
    for f in findings:
        where = f["file"] + (f":{f['line']}" if f["line"] else "")
        print(f"[{SEV_ICON[f['severity']]} {SEV_AR[f['severity']]}] {f['type']}" + (f"  ({f['repo']})" if f.get("repo") else ""))
        print(f"   المكان : {where}")
        if f.get("commit"):
            print(f"   Commit : {f['commit']}  {f.get('author') or ''}  {f.get('date') or ''}")
        print(f"   الحالة : {status_txt(f)}")
        print(f"   القيمة : {f['secret']}")
        print(f"   الحل   : {f['fix']}\n")
    c = Counter(f["severity"] for f in findings)
    act = sum(1 for f in findings if f["status"] in ("active", "staged"))
    his = sum(1 for f in findings if f["status"] == "history")
    print("─" * 60)
    print(f"الإجمالي: {len(findings)} | 🔴 {c['high']}  🟠 {c['medium']}  🟡 {c['low']} | نشط: {act} | في التاريخ بس: {his}")
    print(f"درجة الأمان: {score(findings)}/100")
    if his:
        print("\nللأسرار اللي في التاريخ: 1) ألغِ/غيّر المفتاح الأول  2) نضّف التاريخ: --gen-replace secrets.txt ثم\n"
              "   git filter-repo --replace-text secrets.txt  (على clone جديد) ثم force-push.")


def public(f):
    return {k: v for k, v in f.items() if k != "_raw"}


def write_json(findings, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"tool": "secrets-scanner", "version": VERSION, "generated": datetime.now().isoformat(timespec="seconds"),
                   "score": score(findings), "findings": [public(f) for f in findings]}, fh, ensure_ascii=False, indent=2)


def write_sarif(findings, path):
    rules, seen = [], {}
    for f in findings:
        if f["type"] not in seen:
            seen[f["type"]] = len(rules)
            rules.append({"id": f["type"], "name": f["type"], "shortDescription": {"text": f["type"]},
                          "help": {"text": f["fix"]}})
    lvl = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
    results = [{
        "ruleId": f["type"], "ruleIndex": seen[f["type"]], "level": lvl[f["severity"]],
        "message": {"text": f"{f['type']} ({f['secret']}) - {status_txt(f)}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]},
                                            "region": {"startLine": f["line"] or 1}}}],
        "partialFingerprints": {"secretFingerprint/v1": f["fp"]},
    } for f in findings]
    sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
             "runs": [{"tool": {"driver": {"name": "secrets-scanner", "version": VERSION, "rules": rules}}, "results": results}]}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, ensure_ascii=False, indent=2)


def write_html(findings, path):
    e = html.escape
    sc = score(findings)
    col = "#3fb950" if sc >= 80 else "#d29922" if sc >= 50 else "#f85149"
    c = Counter(f["severity"] for f in findings)
    cards = ""
    for f in findings:
        where = e(f["file"]) + (f":{f['line']}" if f["line"] else "")
        meta = f" | commit <code>{e(f['commit'])}</code> {e(f.get('author') or '')} {e(f.get('date') or '')}" if f.get("commit") else ""
        repo = f" <span class='r'>{e(f['repo'])}</span>" if f.get("repo") else ""
        cards += (f"<div class='f {f['severity']}'><b>{SEV_ICON[f['severity']]} {SEV_AR[f['severity']]} — {e(f['type'])}{repo}</b>"
                  f"<div>الملف: <code>{where}</code>{meta}</div><div>الحالة: {e(status_txt(f))}</div>"
                  f"<div>القيمة: <code>{e(f['secret'])}</code></div><div class='fix'>الحل: {e(f['fix'])}</div></div>")
    if not findings:
        cards = "<div class='ok'>✅ مفيش أسرار ظاهرة</div>"
    doc = f"""<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>تقرير فحص الأسرار</title>
<style>body{{margin:0;background:#0f1419;color:#e6edf3;font-family:Tahoma,sans-serif;line-height:1.6}}
.w{{max-width:900px;margin:auto;padding:24px 16px}} h1{{margin:0}} .m{{color:#8b98a5;font-size:13px}}
.top{{display:flex;gap:16px;align-items:center;flex-wrap:wrap;background:#1a212b;border-radius:12px;padding:16px;margin:16px 0}}
.sc{{width:90px;height:90px;border-radius:50%;border:8px solid {col};display:flex;align-items:center;justify-content:center;font-size:26px;font-weight:bold}}
.p{{padding:4px 12px;border-radius:99px;border:1px solid #2d3846;margin:2px}}
.f{{background:#1a212b;border-right:4px solid #2d3846;border-radius:8px;padding:10px 14px;margin-bottom:10px}}
.f.high{{border-color:#f85149}} .f.medium{{border-color:#f0883e}} .f.low{{border-color:#d29922}}
code{{direction:ltr;unicode-bidi:embed;background:#0008;padding:2px 6px;border-radius:4px;word-break:break-all}}
.fix{{color:#8b98a5;font-size:14px}} .r{{color:#58a6ff;font-weight:normal;font-size:13px}} .ok{{text-align:center;font-size:20px;color:#3fb950;padding:24px}}
@media print{{body{{background:#fff;color:#000}}.f,.top{{background:#fff;border:1px solid #ccc}}}}</style></head><body><div class="w">
<h1>🔐 تقرير فحص الأسرار</h1><div class="m">{datetime.now():%Y-%m-%d %H:%M} | Secrets Scanner v{VERSION}</div>
<div class="top"><div class="sc">{sc}</div><div><div>درجة الأمان من 100</div>
<span class="p">الإجمالي {len(findings)}</span><span class="p">🔴 {c['high']}</span><span class="p">🟠 {c['medium']}</span><span class="p">🟡 {c['low']}</span></div></div>
{cards}</div></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


def write_replace(findings, path):
    seen, n = set(), 0
    with open(path, "w", encoding="utf-8") as fh:
        for f in findings:
            raw = f["_raw"]
            if f["type"] in ("Private Key",) or f["type"].endswith(("file", "Credentials file", "ملف .env")) \
                    or "\n" in raw or raw in seen or f["type"].startswith(("Key/Cert", "npmrc")):
                continue
            seen.add(raw)
            fh.write(f"{raw}==>***REMOVED***\n")
            n += 1
    print(f"ملف الاستبدال اتكتب: {path} ({n} قيمة). ⚠️ فيه الأسرار نفسها: امسحه بعد الاستخدام ومتحطوش على git.")
    print("   ملحوظة: الملفات الحساسة (.env / المفاتيح الخاصة) بتتشال بـ: git filter-repo --path <الملف> --invert-paths")


def install_hook(root):
    hooks = os.path.join(root, ".git", "hooks")
    if not os.path.isdir(hooks):
        sys.exit("مش ريبو git: مفيش .git/hooks")
    hp = os.path.join(hooks, "pre-commit")
    script = os.path.abspath(__file__).replace("\\", "/")
    with open(hp, "w", newline="\n") as fh:
        fh.write(f'#!/bin/sh\nPY=$(command -v python3 || command -v python)\n'
                 f'"$PY" "{script}" . --staged --fail-on high || {{ echo "❌ commit اتمنع: لقيت أسرار. (لتجاوز: git commit --no-verify)"; exit 1; }}\n')
    os.chmod(hp, 0o755)
    print(f"✅ pre-commit hook اتركّب في {hp}")


# ───────────────────────── main ─────────────────────────
def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="Secrets Scanner v" + VERSION, formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="أمثلة: python secrets_scanner.py user/repo --history --html report.html")
    ap.add_argument("target", nargs="?", default=".", help="فولدر محلي | لينك ريبو | user/repo")
    ap.add_argument("--user", help="افحص كل ريبوهات يوزر جيت هاب")
    ap.add_argument("--include-forks", action="store_true", help="مع --user: ضم الـ forks")
    ap.add_argument("--max-repos", type=int, default=30, help="مع --user: أقصى عدد ريبوهات (افتراضي 30)")
    ap.add_argument("--history", action="store_true", help="افحص تاريخ الـ commits كمان")
    ap.add_argument("--staged", action="store_true", help="افحص التغييرات الـ staged بس (للـ pre-commit)")
    ap.add_argument("--all-files", action="store_true", help="تجاهل .gitignore وافحص كل الملفات")
    ap.add_argument("--json", metavar="FILE")
    ap.add_argument("--html", metavar="FILE")
    ap.add_argument("--sarif", metavar="FILE")
    ap.add_argument("--baseline", metavar="FILE", help="تجاهل النتايج المسجلة في الـ baseline")
    ap.add_argument("--write-baseline", metavar="FILE", help="سجّل النتايج الحالية كـ baseline")
    ap.add_argument("--ignore-file", metavar="FILE", help="ملف تجاهل (افتراضي .secretsignore للفولدر المحلي)")
    ap.add_argument("--gen-replace", metavar="FILE", help="ولّد ملف لـ git filter-repo --replace-text")
    ap.add_argument("--install-hook", action="store_true", help="ركّب pre-commit hook في الريبو")
    ap.add_argument("--fail-on", choices=["low", "medium", "high"], help="exit code 1 لو لقى سر بالخطورة دي أو أعلى")
    ap.add_argument("--min-severity", choices=["low", "medium", "high"], default="low", help="اعرض من الخطورة دي لفوق")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("-q", "--quiet", action="store_true", help="من غير طباعة النتايج التفصيلية")
    a = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    findings, tmps = [], []

    try:
        if a.install_hook:
            install_hook(a.target)
            return
        if a.user:
            urls = list_user_repos(a.user, token, a.include_forks)[:a.max_repos]
            print(f"لقيت {len(urls)} ريبو لـ {a.user}", file=sys.stderr)
            targets = urls
        else:
            targets = [a.target]

        for t in targets:
            if is_remote(t):
                url = to_url(t)
                label = re.sub(r"(\.git)?/?$", "", url).split("github.com/")[-1]
                print(f"⏳ clone: {label}", file=sys.stderr)
                try:
                    tmp, root = clone(url, token)
                except RuntimeError as ex:
                    print(f"⚠️ تخطيت {label}: {ex}", file=sys.stderr)
                    continue
                tmps.append(tmp)
                pats = load_ignore(a.ignore_file)  # مش بنحمّل .secretsignore من الريبو الغريب
                findings += scan_path(root, a, label, pats)
            else:
                if not os.path.isdir(t):
                    sys.exit(f"المسار مش موجود: {t}")
                pats = load_ignore(a.ignore_file or os.path.join(t, ".secretsignore"))
                if a.staged:
                    res = scan_staged(t, pats)
                    for f in res:
                        f["status"] = "staged"
                        f["repo"] = None
                    findings += sorted(res, key=lambda f: -SEV_ORDER[f["severity"]])
                else:
                    findings += scan_path(t, a, None, pats)
    finally:
        for tmp in tmps:
            shutil.rmtree(tmp, onerror=_rm)

    if a.baseline and os.path.isfile(a.baseline):
        with open(a.baseline, encoding="utf-8") as fh:
            known = set(json.load(fh))
        findings = [f for f in findings if f["fp"] not in known]
    if a.write_baseline:
        with open(a.write_baseline, "w", encoding="utf-8") as fh:
            json.dump(sorted({f["fp"] for f in findings}), fh, indent=1)
        print(f"baseline اتحفظ: {a.write_baseline} ({len(findings)} نتيجة)")
    findings = [f for f in findings if SEV_ORDER[f["severity"]] >= SEV_ORDER[a.min_severity]]

    if not a.quiet:
        print_text(findings)
    if a.json:
        write_json(findings, a.json); print(f"JSON: {a.json}")
    if a.html:
        write_html(findings, a.html); print(f"HTML: {a.html}")
    if a.sarif:
        write_sarif(findings, a.sarif); print(f"SARIF: {a.sarif}")
    if a.gen_replace:
        write_replace(findings, a.gen_replace)
    if a.fail_on and any(SEV_ORDER[f["severity"]] >= SEV_ORDER[a.fail_on] for f in findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
