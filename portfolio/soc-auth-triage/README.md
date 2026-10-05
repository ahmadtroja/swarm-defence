# SOC Authentication Triage

Group failed authentications by source and flag successful logins after repeated failures.

**Live demo:** https://ahmadtroja-security-it-lab.netlify.app/soc-auth-triage/

## Why this project

Demonstrates practical SOC analyst / JavaScript / Detection engineering skills with an inspectable decision engine, synthetic fixtures and exportable results. Built with AI assistance; all decision rules are explicit in `engine.mjs`.

## Try it

Open the live demo, edit the sample JSON, run analysis and export results. All processing occurs in-browser. Input is never sent to a server.

## Run locally

Requires Python 3 for a local web server and Node.js 18+ for tests. No npm dependencies.

```sh
python3 -m http.server 8000
# Open http://localhost:8000
node test.mjs
```

## Architecture

- `engine.mjs`: pure validation and analysis function
- `sample.json`: synthetic input fixture
- `app.mjs`: accessible input, safe text rendering and JSON export
- `test.mjs`: executable checks for sample outcomes and invalid inputs
- GitHub Pages serves static files from `main`

## Methodology and limitations

Equal timestamps do not establish ordering. A ten-minute window and three failures are illustrative thresholds; events are grouped by source and user. This is a local event analyzer, not a SIEM.

The demo is an educational portfolio artifact. No production integrations, vendor certification or measured operational outcomes are claimed.

## Interview walkthrough

1. Explain the input schema and decision rule.
2. Change a record and predict the output.
3. Discuss false positives, missing context and escalation.
4. Describe how to add authenticated integrations and organization-approved policy.

## License

MIT.
