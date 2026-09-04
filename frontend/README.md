# SecureMail dashboard

React/Vite dashboard for the canonical `securemail.report/v1` contract.

```bash
nvm use
npm ci
npm run dev
```

Vite proxies `/api` to `http://127.0.0.1:8000`. The dashboard reads catalog
reports from the FastAPI service; uploaded report previews stay in browser
memory.

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
