# Security & IT Lab

Five independent browser tools with public source, synthetic fixtures, tests and transparent limitations.

Portfolio: https://ahmadtroja-security-it-lab.netlify.app

- [SOC Authentication Triage](https://ahmadtroja-security-it-lab.netlify.app/soc-auth-triage/) — [source](./soc-auth-triage/)
- [Cloud IAM Policy Review](https://ahmadtroja-security-it-lab.netlify.app/cloud-iam-policy-review/) — [source](./cloud-iam-policy-review/)
- [SAP Access Conflict Review](https://ahmadtroja-security-it-lab.netlify.app/sap-sod-access-review/) — [source](./sap-sod-access-review/)
- [IT Incident Priority Planner](https://ahmadtroja-security-it-lab.netlify.app/it-incident-priority/) — [source](./it-incident-priority/)
- [Vulnerability Remediation Planner](https://ahmadtroja-security-it-lab.netlify.app/vulnerability-remediation-planner/) — [source](./vulnerability-remediation-planner/)

## Verification

Each project passed Node decision-engine tests and Playwright checks for sample results, invalid input, reset, JSON download and mobile width.

## Local use

Run `python3 -m http.server 8000 --directory portfolio`, then open http://localhost:8000. Run `node portfolio/<project>/test.mjs` for project tests.

[LinkedIn drafts](LINKEDIN-POSTS.md)
