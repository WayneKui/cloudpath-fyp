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

## How to use CloudPath

### 1. Create an account
Register with an email and password. Passwords must contain an uppercase letter, a lowercase letter, a digit, and a special character. A fresh account lands on the **Connect** page automatically; a returning account with credentials already saved goes straight to the **Scanner** dashboard.

### 2. Connect a cloud account
On the **Connect** page, switch between the AWS and GCP tabs — each walks through its own setup:

**AWS:**
1. Deploy the provided CloudFormation template in your AWS account (link + your unique Scanner Account ID and External ID are shown on the page — the template creates a read-only IAM role that trusts CloudPath specifically).
2. Copy the Role ARN from the CloudFormation stack's Outputs tab, paste it into the form, and click **Save credential**. Saving immediately attempts `sts:AssumeRole` — if your trust policy isn't set up correctly, you'll see the AWS error right away rather than finding out at scan time.
3. Use **Test connection** any time afterward to re-verify.

**GCP:**
1. Create a service account with the Viewer and Security Reviewer roles (a ready-to-paste `gcloud` command is provided).
2. Download its JSON key, paste the full contents into the form, and click **Save credential**.

Once saved, the tab shows a green "Connected" status with the account ID / project ID. You can remove a saved credential at any time from the same page (**Remove this credential** — CloudPath won't be able to scan that account until you reconnect it).

### 3. Run a scan
From the **Scanner** dashboard, click **Run Scan**. A full scan ingests your cloud resources (via Cartography), runs compliance checks (via Prowler), and correlates everything into attack paths — this typically takes 10–15 minutes and runs in the background, so the page stays responsive while it works.

### 4. Read the results
- **KPI cards** at the top summarize path counts by severity (Critical / High / Medium / Low).
- The **attack graph** visualizes every chained path — switch between Hierarchy, Force, and Circle layouts using the buttons above it. Nodes are colored by MITRE tactic; cross-cloud bridging edges (AWS → GCP) are drawn in a distinct solid cyan line versus same-cloud dashed edges.
- The **path list** alongside the graph shows each attack chain's risk score, MITRE technique sequence, and a "Cross-Cloud" badge where relevant — fully expanded, no extra clicks needed.

### 5. Review scan history
The **History** page lists every past scan (manual, scheduled, or API-triggered) with its status and per-severity counts. Free tier retains the last 5 scans; Plus and Max retain unlimited history.

### 6. Automate scans (Plus tier and above)
Click **⏱ Schedule** on the dashboard to set a daily or weekly scan time. Only one active schedule per account — saving a new time updates the existing schedule rather than creating a duplicate.

### 7. Write your own detection rules
The **Rules** page shows the 4 built-in detection rules (read-only) alongside any custom rules you've written. Click **+ New Rule** to build one either through the Guided point-and-click form or by writing raw Cypher directly in Advanced mode — the Cypher is checked for safety as you type (no write clauses, no dangerous procedures) before you're allowed to save it. Custom rules run automatically alongside the built-in ones on every future scan.

### 8. Automate with the API (Max tier)
From **API & Integrations**, generate an API key (shown once — copy it immediately) to call the REST API from your own scripts or CI pipeline, and register webhooks to get pushed a notification the moment a scan completes. See the [REST API](#rest-api) section below.

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
