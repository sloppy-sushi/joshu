# CodeQL and "Unsafe jQuery plugin" alerts

## Why you see those alerts

CodeQL scans JavaScript and flags **jquery.validate.js** in `wwwroot/lib` as "Unsafe jQuery plugin." That file is **third-party vendor code**; we don’t fix it in place, and fixing one line often causes new alerts elsewhere.

## What this repo does

- **`.github/workflows/codeql.yml`** runs CodeQL **only for C#** (no JavaScript/TypeScript).
- So **jquery.validate.js is not scanned** and new "Unsafe jQuery plugin" alerts should not appear.

## If you still see "Unsafe jQuery plugin" alerts

1. **Dismiss existing alerts**  
   They may be from an old run when JS was still in the matrix.  
   In GitHub: **Security → Code scanning** → open each alert → **Dismiss** → e.g. **"Won't fix"** or **"False positive".**

2. **Use only one CodeQL workflow**  
   If you have **another** CodeQL workflow (e.g. `codeql-analysis.yml` from the Security tab):
   - Either **delete** that workflow so only `codeql.yml` runs, or  
   - Edit it and **remove** `javascript-typescript` from the `matrix.language` list so it only runs C#.

3. **Confirm what’s on the default branch**  
   The workflow that runs on push/PR is the one on your **default branch** (e.g. `main`).  
   Make sure that file has `language: [ 'csharp' ]` only (no `javascript-typescript`).

After that, new CodeQL runs won’t scan `wwwroot/lib`, and you can keep the app’s C# code in CodeQL without those jQuery plugin alerts.
