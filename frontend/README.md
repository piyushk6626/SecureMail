# SecureMail dashboard

React/Vite dashboard for the canonical `securemail.report/v1` contract.

```bash
nvm use
npm ci
npm run dev
```

Vite proxies `/api` to `http://127.0.0.1:8000`. Operator and analyst docs:
[dashboard workflows](../docs/user-guide/dashboard-workflows.md) and
[first dashboard run](../docs/getting-started/first-dashboard-run.md).

Checks:

```bash
npm run lint
npm run typecheck
npm run test
npm run build
npm run test:e2e
```

Regenerate checked-in report types after changing the canonical schema:

```bash
npm run generate:types
```
