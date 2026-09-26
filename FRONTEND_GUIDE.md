# Frontend User Guide — Security Compliance Auditor (SIH 26155)

Repo: https://github.com/Satish-vaishyar/Multi-Vendor-Security

React 19 + Vite + Tailwind frontend in `frontend/`. It talks to the FastAPI backend
(`backend/`, 42 routes under `/api/v1`). The frontend never touches devices —
uploads are analyzed locally and findings/remediation are dry-run only.

## 0. Get the code

```powershell
git clone https://github.com/Satish-vaishyar/Multi-Vendor-Security.git
cd Multi-Vendor-Security
```

## 1. Prerequisites

- Node.js 18+ and npm
- Backend running (the frontend is only a UI shell without it)

## 2. Start the app (two terminals)

**Terminal 1 — backend (from repo root):**

```powershell
cd F:\Multi-vendor\backend
copy .env.example .env
uv sync
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — frontend (from repo root):**

```powershell
cd F:\Multi-vendor\frontend
npm install
npm run dev
```

Then open the URL Vite prints (default `http://localhost:5173`).

> The frontend points at the backend via `frontend/.env.development`:
> `VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1`.
> If your backend runs elsewhere, edit that file and restart `npm run dev`.

## 3. Login

- Open the app → you land on **Login**.
- Demo credentials: `admin@example.com` / `admin123` (email pre-filled — type the password).
- Click **Sign In** → you go to **Dashboard**.

## 4. Test flow with the sample files (happy path)

Sample configs live in `test-files/` (see `test-files/README.md` for what each proves).
Start with `test-files/01-cisco-insecure-router.txt`.

### Step 1 — Upload

1. Sidebar → **Upload** (or **Configurations → Upload Configuration**).
2. **Configuration Files** card: drag & drop the file (or Browse). Single file =
   single-upload path; selecting several files = bulk-upload path.
3. **Vendor / Platform** fields: leave blank — auto-detection handles all 7 sample
   files. Fill them only to override detection.
4. **Target Asset** card: either pick an existing asset or keep **Create new asset**
   and fill in its details (name is required) — every asset is stored in Postgres.
5. Click **Upload**. On success you see `Uploaded — detected CISCO…` and are taken
   to the **Configuration details** page.

### Step 2 — Inspect the configuration

On the Configuration details page there are 4 tabs:

| Tab | What it shows |
|---|---|
| Raw Configuration | The file you uploaded (read-only). |
| Canonical IR | Normalized vendor-neutral JSON the engines audit. Open this to confirm parsing worked. |
| Unknown Tokens | Lines the parser didn't recognize → these feed the **Training** page. Try `07-edge-unknown-tokens.txt` here. |
| Parsing Information | Parser type + confidence. |

### Step 3 — Start an audit

1. Click **Start Audit** (top right).
2. Frameworks: keep all checked (`CIS`, `NIST`, `STIG`, `ISO27001`) for the full run.
3. Engines: keep **CVE analysis**, **PQC analysis**, **Security analytics** checked.
   Check **Generate PDF report** too if you want a downloadable report in one step.
4. Click **Start Audit** in the dialog → you land on the **Audit progress** page,
   which polls every ~2.5 s through Ingestion → Detection → Normalization →
   Compliance → CVE → PQC → Security → Risk → Report.
5. Click **View Results** when status is `COMPLETED`.

### Step 4 — Read results

| Page | What to check |
|---|---|
| Audit Results (`/audits/:id/results`) | Compliance score, per-framework scores, findings breakdown. Insecure file 01 should score clearly lower than secure file 02. |
| Compliance | Per-control pass/fail per framework. |
| Vulnerabilities | CVE matches for the detected version (best with file 04, FortiOS 7.2.2). Click one for details + blast radius. |
| PQC | Quantum-readiness findings (weak RSA/DH flagged). |
| Security Analytics | Anomaly/ML-based findings. |
| Findings | All findings across audits; click a row for evidence + fix guidance. |
| Reports | Generate/download the PDF audit report (if not generated at audit time). |
| Remediation | Approve a finding → dry-run apply with corrected config (device is never touched — `device_touched: false`). |
| Training | Unknown-token queue from file 07 → Suggest mapping → Approve. |
| Assets | Asset inventory (created inline at upload or via Assets page). |
| Settings | App/token settings. |

## 5. Suggested test script (10 minutes)

1. Login with the demo account.
2. Upload `01-cisco-insecure-router.txt` → audit with everything on → note the score.
3. Upload `02-cisco-secure-router.txt` → same audit → confirm its score is higher.
4. Bulk-upload `03`, `04`, `05`, `06` together → run one audit each → check the
   **Audits** page lists them and vendor detection is right (Juniper / Fortinet /
   Palo Alto / Arista).
5. Upload `07-edge-unknown-tokens.txt` → **Unknown Tokens** tab → **Training** page.
6. From an audit: open Vulnerabilities, PQC, Analytics, then Reports → download PDF.
7. Pick a compliance finding → Remediation → Approve → dry-run apply.

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| Login fails / `Network Error` | Backend isn't running or URL mismatch. Check `http://127.0.0.1:8000/docs` loads, and `frontend/.env.development` matches it. Restart `npm run dev` after edits. |
| Upload rejected (`empty configuration` / too large) | Backend limit is 5 MB, non-empty UTF-8 text; `.txt .cfg .conf .json .xml .text .log` are natively accepted (others still accepted with a warning). |
| Audit stuck in QUEUED/RUNNING | Backend runs audits synchronously in-process; keep the backend terminal alive and retry. Check backend logs for tracebacks. |
| No findings / score looks wrong | Confirm **Canonical IR** tab is non-empty and frameworks/engines were checked at Start Audit. Re-run with all boxes ticked. |
| Blank pages / 404 on refresh | This is a SPA — serve via `npm run dev`, not by opening files directly. |
| Port 5173 busy | Run `npm run dev -- --port 5174`. No backend change needed. |

## 7. Notes for evaluators / demo

- Best single-file demo: `01-cisco-insecure-router.txt` (many colored findings in
  ~1 minute) followed by `02-cisco-secure-router.txt` (score comparison).
- Best multi-vendor demo: bulk-upload `03`–`06` to show vendor auto-detection
  across Juniper / Fortinet / Palo Alto / Arista.
- Nothing in this flow contacts real network devices; remediation Apply is always
  a dry run (`device_touched: false`).
