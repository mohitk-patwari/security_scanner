# NetGuard — IaC Security Analyzer

**Team 18 · MSRIT · CSP67 Mini Project**

NetGuard scans Terraform and Kubernetes in pull requests, builds a network topology graph, scores risk with deterministic rules plus LLM enrichment, and can propose autofixes posted back to GitHub PRs.

**Live demo:** [https://net-guard-msrit.vercel.app/](https://net-guard-msrit.vercel.app/)

**Repository:** [https://github.com/iyertrisha/security_scanner](https://github.com/iyertrisha/security_scanner)

---

## How it works

### End-to-end flow

1. **Customer IaC repo (e.g. [demo-guard](https://github.com/iyertrisha/demo-guard))** — A GitHub Actions workflow runs on every PR, collects all `.tf` / `.yaml` / `.yml` files, HMAC-signs the payload, and POSTs to `NETGUARD_API_URL/api/scan`.
2. **Backend API (EC2, port 8000)** — Orchestrates parser → graph engine → risk scorer, persists scans/findings in PostgreSQL, applies org-scoped auth via `X-API-Key`.
3. **Parser (8001)** — Normalizes Terraform and Kubernetes into a shared resource schema.
4. **Graph engine (8002)** — Builds nodes/edges (VPC, subnets, SGs, EC2, RDS, S3, K8s workloads) and PR-level diffs for blast-radius analysis.
5. **Risk scorer (8003)** — Deterministic rules (public ports, permissive IAM, unencrypted storage, cross-resource chains such as **internet-facing EC2 + admin IAM**) plus optional Gemini LLM ±1 severity enrichment.
6. **GitHub Actions** — Posts a summary comment on the PR; fails the check if HIGH/CRITICAL findings remain (merge gate).
7. **Web UI (Vercel)** — Same-origin proxy to the API (`/api/*` → EC2). Users sign up, view scan history, explore the D3 graph, run **Suggest fix**, and **Post to GitHub PR** with a confirmation dialog.

### Deployment model (production demo)

| Component | Host | Notes |
|-----------|------|--------|
| Frontend | [Vercel](https://net-guard-msrit.vercel.app/) | React + Vite; `vercel.json` rewrites `/api` to the API |
| API + microservices + Postgres | AWS EC2 | Docker Compose: `db`, `parser`, `graph_engine`, `risk_scorer`, `api` |
| Sample flawed IaC | [demo-guard](https://github.com/iyertrisha/demo-guard) | Breach-inspired branches for NetGuard CI demos |

### Architecture (local / EC2)

| Service | Port | Role |
|---------|------|------|
| API | 8000 | Auth, scans, autofix, GitHub comment posting |
| Parser | 8001 | IaC parsing |
| Graph engine | 8002 | Topology + PR diff |
| Risk scorer | 8003 | Rules + LLM |
| PostgreSQL | 5432 | Scans, findings, fix proposals |
| Frontend (dev) | 5173 | `npm run dev` in `frontend/` |

---

## Demo videos

Recordings are in **Git LFS** under `docs/demos/`. Click a link to open GitHub’s built-in video player on the file page.

| Demo | Watch (GitHub LFS player) |
|------|---------------------------|
| Dashboard, login, and scan overview | [01-netguard-dashboard-and-scan.mov](https://github.com/iyertrisha/security_scanner/blob/main/docs/demos/01-netguard-dashboard-and-scan.mov) |
| PR scan results and findings | [02-pr-scan-and-findings.mov](https://github.com/iyertrisha/security_scanner/blob/main/docs/demos/02-pr-scan-and-findings.mov) |
| LLM autofix and post comment to GitHub PR | [03-autofix-and-github-pr-comment.mov](https://github.com/iyertrisha/security_scanner/blob/main/docs/demos/03-autofix-and-github-pr-comment.mov) |

After clone, run `git lfs pull` to download the `.mov` files locally.

---

## Quick start (local)

```bash
git clone https://github.com/iyertrisha/security_scanner.git
cd security_scanner
git lfs pull

cp .env.example .env   # set DATABASE_URL, GEMINI_API_KEY, GITHUB_TOKEN, etc.
python3.12 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

docker compose up -d db parser graph_engine risk_scorer api

cd frontend && npm install && npm run dev
# UI: http://localhost:5173   API: http://localhost:8000
```

Run tests:

```bash
pytest
```

### Connect a GitHub IaC repo

1. Sign up at the [live app](https://net-guard-msrit.vercel.app/) or via `POST /api/auth/signup`.
2. In **Settings**, copy your API key and HMAC secret.
3. In your IaC repo, add secrets: `NETGUARD_API_URL`, `NETGUARD_SECRET`, `NETGUARD_API_KEY`.
4. Copy `.github/workflows/netguard.yml` and `scripts/post_pr_findings.py` from this repo.
5. Open a PR — NetGuard scans, comments, and blocks on critical findings.

---

## Project layout

```
security_scanner/
├── .github/workflows/netguard.yml
├── services/           # api, parser, graph_engine, risk_scorer, autofix, database
├── parser-service/     # Standalone parser package + benchmarks
├── frontend/           # React UI (also deployed separately to Vercel)
├── docker/             # Dockerfiles
├── docker-compose.yml
├── migrations/
├── scripts/post_pr_findings.py
├── docs/demos/         # Screen recordings (Git LFS)
└── tests/
```

---

## Security note

Do not commit real API keys. Use `.env` locally and GitHub/Vercel secrets in production. The bundled [demo-guard](https://github.com/iyertrisha/demo-guard) IaC is intentionally vulnerable — never apply it to a real AWS account.
