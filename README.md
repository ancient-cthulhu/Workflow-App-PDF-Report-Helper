# Workflow App PDF Report Helper

Posts one pull-request comment with a PDF report built from your Veracode SAST,
SCA and IaC/Secrets findings: an executive summary, then every finding with its
severity, exact location, identifier and remediation detail.

Standard library only, no dependencies. It reads scan output and comments.

## Install

This drops into the **Veracode `github-actions-integration` repo**, the one
that runs your scans centrally. Nothing in the application repos changes.

### 1. Add the helper files

Copy into the integration repo, keeping the paths:

```
helper/cli/veracode_report.py      CLI: export, build, comment
helper/cli/veracode_findings.py    Parsers, severity model, GitHub helpers
helper/cli/veracode_pdf.py         PDF writer
.github/workflows/veracode-pdf-report.yml
```

`helper/cli/` already exists in the integration repo. Add to it, do not
replace it.

### 2. Add one report job per scan

Each scan lives in a different workflow, so each gets its job in a different
file. The Veracode actions already upload their results as artifacts, so the
scan jobs themselves stay untouched.

**SAST** goes in `.github/workflows/veracode-code-analysis.yml`, after the
existing `pipeline_scan` job:

```yaml
  pdf_report_sast:
    needs: [pipeline_scan]
    if: always()
    uses: ./.github/workflows/veracode-pdf-report.yml
    with:
      scan: pipeline
      results_path: '[0-9]-results.json'
      results_artifact: 'Veracode Pipeline-Scan Results - *.zip'
      scan_repo: ${{ github.event.client_payload.repository.full_name }}
      head_sha:  ${{ github.event.client_payload.sha }}
      blob_ref:  ${{ github.event.client_payload.repository.branch }}
      pr_number: ${{ github.event.client_payload.pr_number }}
      token:     ${{ github.event.client_payload.token }}
      runs_on:   ${{ github.event.client_payload.user_config.default_runs_on }}
```

**SCA** goes in `.github/workflows/veracode-sca-scan.yml`, after the
`veracode-sca-scan` job:

```yaml
  pdf_report_sca:
    needs: [veracode-sca-scan]
    if: always()
    uses: ./.github/workflows/veracode-pdf-report.yml
    with:
      scan: sca
      results_path: scaResults.txt
      results_artifact: 'Veracode Agent Based SCA Results'
      scan_repo: ${{ github.event.client_payload.repository.full_name }}
      head_sha:  ${{ github.event.client_payload.sha }}
      blob_ref:  ${{ github.event.client_payload.repository.branch }}
      pr_number: ${{ github.event.client_payload.pr_number }}
      token:     ${{ github.event.client_payload.token }}
      runs_on:   ${{ github.event.client_payload.user_config.default_runs_on }}
```

**IaC/Secrets** goes in `.github/workflows/veracode-iac-secrets-scan.yml`,
after the `veracode-iac-secrets-scan` job:

```yaml
  pdf_report_iac:
    needs: [veracode-iac-secrets-scan]
    if: always()
    uses: ./.github/workflows/veracode-pdf-report.yml
    with:
      scan: iac
      results_path: results.json
      results_artifact: 'Veracode Container IaC Secrets Scanning Results'
      scan_repo: ${{ github.event.client_payload.repository.full_name }}
      head_sha:  ${{ github.event.client_payload.sha }}
      blob_ref:  ${{ github.event.client_payload.repository.branch }}
      pr_number: ${{ github.event.client_payload.pr_number }}
      token:     ${{ github.event.client_payload.token }}
      runs_on:   ${{ github.event.client_payload.user_config.default_runs_on }}
```

That is the whole installation. No new secrets, no changes to any application
repo, no changes to the existing scan jobs.

### Things worth knowing about these snippets

- **`token` is `client_payload.token`.** The integration already receives a
  token scoped to the scanned repo and passes it to every job that touches
  that repo. The report uses the same one. `GITHUB_TOKEN` is scoped to the
  integration repo and cannot comment on the app repo, so do not substitute
  it. The workflow warns at startup if the token is missing.
- **`runs_on` is `user_config.default_runs_on`**, matching every other job in
  the integration, so the report runs on the same runner as the scans,
  self-hosted included.
- **`if: always()`** matters. The scan jobs fail the build on policy findings,
  and that is exactly when you want a report.
- **`results_path` is `[0-9]-results.json`**, one file per matrix leg. The
  filtered files are named `0-filtered_results.json`, with an underscore before
  `results`, so this pattern excludes them and you get the unfiltered findings.
- **The `*.zip` suffix is deliberate.**
- **Thresholds come from the `threshold` input, nothing else.** A stock
  Veracode integration has no severity threshold in `veracode.yml`, so there is
  nothing to read. See below if you want per-repo control.

### Verifying it works

Dispatch a scan against a repo with an open PR, then check, in order:

1. The `pdf_report_*` job ran and is green. It is `continue-on-error`, so a
   red X is unusual and worth reading.
2. The job log shows `Using results file: ...` and
   `Exported N ... finding(s)`. If it says no results file matched, your
   `results_path` or `results_artifact` is wrong.
3. The run summary carries the full report tables.
4. A **Veracode Security Report** comment is on the pull request.

If steps 1 to 3 pass but no comment appears, it is the token. The log will say
so.

### Inputs

| Input | Required | Notes |
|:--|:--|:--|
| `scan` | yes | `pipeline`, `sca` or `iac` |
| `results_path` | yes | Relative path or glob, newest non-empty match wins |
| `results_artifact` | no | Artifact to download results from. Omit if already in the workspace |
| `scan_repo` | yes | The **scanned** app repo, `client_payload.repository.full_name` |
| `token` | yes | `client_payload.token`. Reaches the scanned repo |
| `runs_on` | no | JSON runner label, `user_config.default_runs_on` |
| `head_sha` | yes | Keys the report to a commit |
| `blob_ref` | no | Branch for source links, defaults to `head_sha` |
| `pr_number` | no | Resolved from the commit if empty |
| `threshold` | no | `critical`/`high`/`medium`/`low`/`info` or a CVSS number, default `medium` |
| `page_size` | no | `a4` or `letter` |
| `publish_branch` | no | Commit the PDF to this branch of the scanned repo |
| `include_outdated` | no | SCA text reports, adds Outdated Library issues |
| `retention_days` | no | Artifact retention, default 30 |

Permissions the workflow requests apply to the **scanning** repo: `contents:
read` to check out the helper, `actions: read` to collect sibling fragments.
Everything touching the scanned repo goes through `comment_token`, which needs
Pull requests: write, Contents: read for source links, and Contents: write only
if you set `publish_branch`.

### Pipeline results

`1-results.json` is every finding. `1-filtered_results.json` is only what
survived your policy's severity filter. A real run analysing 71 issues wrote 13
to the filtered file, skipping 50 Medium and 8 Low. Gate on the filtered file,
report on the unfiltered one, or the PDF reads far cleaner than the code is.

## How it works

The three scans finish at different times, so no single job sees all of them.
Each report job:

1. **exports** its findings to a fragment, uploaded as
   `veracode-findings-<sha>-<scan>`
2. **builds** the PDF, first collecting any sibling fragment already published
   for the same commit
3. **comments**, updating one sticky comment

Whichever scan finishes last produces the full three-scan document. Everything
is keyed on the commit SHA, so a new commit gets a fresh report in the same
comment, and findings never leak between commits.

## What to expect

**In the PDF.** A summary page (counts by severity, per-scan coverage, a *Where
to start* priority list), then one section per scan with a card per finding:
severity and CVSS, CWE/CVE/GHSA linked to MITRE/NVD/GitHub Advisories,
`path/file.cs:214` linked to that line, function name, package and fixed
version, and the scanner's remediation text. Plus the SCA Update Advisor table
when the scan emits one. Bookmarks, page numbers, clickable links.

**In the comment.** Severity counts, a per-scan table, the highest-severity
findings, and a link to the PDF.

**Scans that have not reported show as pending.** Same if a
parser cannot trust its own output: if fewer SCA rows parse than the agent's
own summary claims, that scan is marked pending rather than passing, so a
format change upstream can never render a falsely clean report.

**Only pull requests get a comment.** On a push or manual dispatch it still
builds the PDF, uploads the artifact and writes the workflow run summary.

**Nothing here breaks your pipeline.** Missing results, malformed output, an
invalid threshold, an unreachable API or a token without comment permission all
produce a warning and exit 0.

## Notes

- Attaching a file to a comment is not possible via the GitHub API, so the PDF
  is always linked rather than embedded.
- Artifacts expire after 30 days by default, and the comment link with them.
- Findings are ranked on the higher of the reported severity and the CVSS band,
  so an "Unknown" carrying a 9.1 is not under-rated. No usable signal floors to
  high for secrets, medium otherwise.
- Text is WinAnsi, so CJK in a description will not render. The finding still
  appears.
- .NET SAST lowercases paths. They are resolved against the real repo tree to
  fix the links, which needs `contents: read` and a valid `blob_ref`.
- Secret-looking values in IaC source lines are redacted before they reach the
  PDF or the comment.

### Running locally

```bash
python3 helper/cli/veracode_report.py export \
    --mode sca --input scaResults.txt --threshold medium --out fragments/sca.json

python3 helper/cli/veracode_report.py build \
    --fragments fragments --out report.pdf
```

`SCAN_REPO`, `HEAD_SHA`, `BLOB_REF`, `PR_NUMBER` drive links and the comment;
`GH_TOKEN` resolves paths and posts.


## Support

This is a community overlay for the Veracode GitHub Workflow Integration and is not officially supported by Veracode. When reporting an issue, include the failing job log (the resolved threshold line and the gate table) and the relevant `veracode.yml` section.