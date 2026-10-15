# ماسح الأسرار v2 (Secrets Scanner)

- `secrets_scanner.py`: أداة CLI من غير مكتبات (Python 3.8+ و git).
- `index.html`: واجهة ويب عربي بتفحص ريبو جيت هاب عام من المتصفح.
- `.github/workflows/secrets-scan.yml`: فحص تلقائي (push / PR / أسبوعي) + رفع SARIF.

## إيه الجديد في v2
- يفحص **لينك ريبو** أو `user/repo` أو **كل ريبوهات يوزر** (`--user`).
- يفرّق بين سر **موجود في الكود** وسر **اتمسح بس لسه في التاريخ** (التاني لازم يتغير برضه).
- يحترم `.gitignore`، وعنده `.secretsignore` وتجاهل سطر بـ `secrets-scanner:ignore`.
- قواعد أكتر (OpenAI، Anthropic، Supabase، Discord، SendGrid، npm...) وفحص ملفات حساسة بالاسم (`.env`, `id_rsa`...).
- بيفك الـ JWT: `service_role` خطر، و`anon` عادي ومش بيتبلغ عنه.
- تقارير: HTML (درجة أمان) + JSON + SARIF.
- `--baseline` عشان تتجاهل النتايج القديمة وتشوف الجديد بس.
- `--staged` + `--install-hook`: يمنع الـ commit لو فيه سر.
- `--gen-replace`: يولّد ملف لـ `git filter-repo`.

## الاستخدام (PowerShell)
```powershell
python secrets_scanner.py . --history
python secrets_scanner.py https://github.com/user/repo --history --html report.html
python secrets_scanner.py --user Gawad-x1 --history --html all.html
python secrets_scanner.py . --install-hook
python secrets_scanner.py . --history --gen-replace secrets.txt
```
للريبوهات الخاصة أو لرفع حد الـ API:
```powershell
$env:GITHUB_TOKEN = "ghp_xxx"
```

## تنضيف التاريخ
1. غيّر/ألغِ المفتاح الأول (ده الأهم).
2. `git clone` جديد، وبعدين `git filter-repo --replace-text secrets.txt` وأخيراً `git push --force`.
3. امسح `secrets.txt` بعد الاستخدام.

## النشر
الواجهة ملف واحد: ارفع على جيت هاب واربط بـ Vercel (من غير build ولا env vars).
