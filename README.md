# CloudPath

**Multi-cloud attack path engine.** CloudPath correlates misconfigurations across AWS and GCP into the attack chains a real intruder would actually walk — instead of another flat list of findings to triage.

> Traditional CSPM tools (Prowler, Cartography, native cloud security scanners) tell you *what's* misconfigured. They don't tell you which of those misconfigurations, chained together, actually get an attacker from "public EC2 instance" to "your GCP production bucket." CloudPath does.

---

## Why it exists

Cloud security teams drown in findings. A single Prowler scan can surface hundreds of "FAIL" checks, and most of them are noise in isolation — an overly permissive IAM role only matters if something can actually reach it. CloudPath's detection engine walks the resource graph (built on [Cartography](https://github.com/cartography-cncf/cartography)) and chains individual misconfigurations into MITRE ATT&CK-mapped attack paths, scored by exploitability and blast radius.

Its standout capability is **cross-cloud correlation**: detecting when an AWS Secrets Manager secret contains a GCP service account key, and following that thread into a full AWS → GCP attack chain — a class of risk that single-cloud scanners structurally cannot see, because they never look at the other cloud at all.

## Key features

- **Multi-cloud ingestion** — AWS and GCP resource graphs via Cartography, plus custom ingestors for AWS Secrets Manager
- **Attack path chaining** — MITRE ATT&CK-mapped detection rules chained via graph reachability, not just a flat findings list
- **Cross-cloud correlation** — the novel contribution: AWS ⇄ GCP credential bridging (T1552) that single-cloud tools miss entirely
- **CVSS-aligned risk scoring** — multi-factor scoring (exploitability, blast radius, cross-cloud scope multiplier) grounded in CVSS v3.1 methodology
- **Custom detection rules** — write your own Cypher-based detection rules per account, sandboxed with a keyword blocklist and enforced read-only execution
- **Multi-tenant by design** — per-tenant encrypted credentials, scoped Neo4j queries, isolated scan history
- **Scheduled scans** — daily/weekly recurring scans (Plus tier+)
- **REST API + webhooks** — trigger scans, pull attack paths, and receive push notifications on scan completion (Max tier)
- **Compliance exports** — CSV/JSON exports of attack paths for audit trails

## How it works

```
Browser ──▶ Flask (auth, dashboard, REST API, billing)
              │
              ├──▶ PostgreSQL   (users, encrypted credentials, scan history, API keys, webhooks)
              ├──▶ Neo4j        (resource graph + attack paths, tenant-scoped)
              │
              └──▶ Scan pipeline (per-user, temporary credentials only)
                     ├─ Cartography            AWS/GCP resource ingestion
                     ├─ Custom ingestors        Secrets Manager, cross-cloud linking
                     ├─ Prowler                 AWS + GCP compliance findings
                     └─ Detection engine         Rule matching → path chaining → scoring
```

Cloud access is read-only and temporary: CloudPath assumes a customer-deployed IAM role via `sts:AssumeRole` with a per-tenant external ID, receives short-lived credentials, and never stores long-lived cloud keys.

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Flask (Python) |
| Relational DB | PostgreSQL (asyncpg) |
| Graph DB | Neo4j |
| Cloud ingestion | [Cartography](https://github.com/cartography-cncf/cartography) |
| Compliance scanning | [Prowler](https://github.com/prowler-cloud/prowler) |
| Auth | Flask-Login, bcrypt, Fernet (credential encryption at rest) |
| Payments | LemonSqueezy |
| Frontend | Server-rendered HTML/JS, Cytoscape.js (graph visualization) |

## Getting started

### Prerequisites
- Python 3.11+
- Docker (for PostgreSQL and Neo4j)
- AWS and/or GCP credentials for the accounts you want to scan

### Setup

```bash
git clone https://github.com/WayneKui/cloudpath-fyp.git
cd cloudpath-fyp
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt

docker compose -f docker-compose.postgres-only.yml up -d
# Run a Neo4j container alongside it (see docker docs for your platform)
```

Copy `.env.example` to `.env` and fill in at minimum `CLOUDPATH_ENCRYPTION_KEY`, `CLOUDPATH_DB_DSN`, and `FLASK_SECRET_KEY` — everything else has a local-dev default or is optional (billing). AWS credentials for the scanner's own AWS calls come from the standard AWS credential chain (env vars, `~/.aws/credentials`, or an IAM instance role), not from `.env`. See `.env.example` for the full list with explanations.

Apply the database schema and migrations:

```bash
docker exec -i <postgres-container> psql -U cloudpath -d cloudpath < schema.sql
for f in migration_*.sql; do docker exec -i <postgres-container> psql -U cloudpath -d cloudpath < "$f"; done
```

Run it:

```bash
python app.py
```

Visit `http://localhost:5000`, register an account, and follow the Connect page to link an AWS role or GCP service account.

## Pricing tiers

| | Free | Plus | Max |
|---|---|---|---|
| On-demand scans | ✓ | ✓ | ✓ |
| Multi-cloud (AWS + GCP) | ✓ | ✓ | ✓ |
| Attack-path detection + MITRE mapping | ✓ | ✓ | ✓ |
| Scheduled scans | — | ✓ | ✓ |
| Scan history retention | — | ✓ | ✓ |
| REST API + API keys | — | — | ✓ |
| Webhooks | — | — | ✓ |
| Compliance export (CSV/JSON) | — | — | ✓ |

## REST API

Max-tier accounts can generate API keys from `/api-management` and authenticate via:

```
Authorization: Bearer cpk_...
```

```bash
curl -H "Authorization: Bearer cpk_..." https://your-instance/api/v1/attack-paths
```

Endpoints cover triggering scans, listing scan history, pulling attack paths, and compliance exports. Full reference available in-app under API & Integrations → Documentation.

## Security

- Cloud credentials are Fernet-encrypted at rest; no long-lived keys are ever stored, only short-lived assumed-role sessions
- Passwords hashed with bcrypt; login is rate-limited (per-account and per-IP)
- Every database and graph query is scoped to the authenticated tenant — no cross-account data access
- Custom detection rules run inside a Neo4j **read-only transaction**, with a keyword blocklist as a first line of defense — a rule can never write to the graph, only read it
- Session cookies are `HttpOnly` and `SameSite=Lax`, with `Secure` enforced in production
- CSV/compliance exports are sanitized against formula-injection payloads

## License

MIT — see [LICENSE](LICENSE).
