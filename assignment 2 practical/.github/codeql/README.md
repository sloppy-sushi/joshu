# CodeQL configuration

This folder contains `codeql-config.yml`, which:

- **paths-ignore:** Excludes `wwwroot/lib` and jQuery Validation from analysis (vendor code).
- **query-filters:** Disables the `js/unsafe-jquery-plugin` query so "Unsafe jQuery plugin" alerts are not raised.

**If you still see "Unsafe jQuery plugin" alerts:** The workflow that runs CodeQL must use this config. Open the workflow that runs CodeQL (e.g. `.github/workflows/codeql.yml` or `codeql-analysis.yml`). In the **Initialize CodeQL** step, ensure it has:

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v4
  with:
    languages: ${{ matrix.language }}
    config-file: ./.github/codeql/codeql-config.yml
```

If you enabled Code scanning from the Security tab, GitHub may have created a different workflow that does **not** include `config-file`. Add the `config-file` line to that workflow, or use the workflow in this repo that already includes it.

After updating the workflow, push and re-run CodeQL. Dismiss any existing "Unsafe jQuery plugin" alerts in the Security tab (e.g. "Won't fix" or "False positive").
