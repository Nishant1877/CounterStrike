# IdentityGuard | 120-Second Hackathon Judge Walkthrough Script
**Challenge A-03:** Session Risk & Account-Takeover Detection Engine  
**Domain 2:** AI Systems & Infrastructure  
**Event:** VORTEXA 3.0 Hackathon (Dr. D. Y. Patil Institute of Technology)

---

## Executive Summary for Judges (30 Seconds)

> "Judges, modern account takeover detection suffers from three critical vulnerabilities:
> 1. **Over-reliance on Black-Box AI:** ML models hallucinate or block legitimate users during network glitches.
> 2. **Session Bleed:** Traditional systems flag an event but allow attackers to keep making API calls under active session tokens.
> 3. **Tamperable Logs:** Internal attackers can alter SQL audit rows to hide unauthorized transactions.
>
> We built **IdentityGuard**: an enterprise deterministic security engine that strictly isolates behavioral signals from ML advisors, guarantees an atomic **HTTP 403 terminal session gate (Invariant R11)**, provides an immutable **SHA-256 cryptographically chained audit log (Invariant R8)**, and features a deterministic **sandboxed replay engine with diff analysis (Invariant R10)**.
>
> Everything is running live right now on `http://127.0.0.1:8000` with zero external dependencies."

---

## 120-Second Live Demonstration Workflow

### Step 1: Benign User Baseline (0:00 - 0:25)
1. **Navigate to Protected Banking App:** `http://127.0.0.1:8000/bank_app.html`
2. **Show the Profile:**
   - User: `Asha Sharma`
   - Device: `dev-asha-macbook` (Verified known device)
   - Location: `Pune, India (IST)`
3. **Execute Action:** Click **"Execute Inquire"** (`view_balance`).
4. **Observe Response:**
   - Status: **200 OK**
   - Result: `NO_ACTION` under rule `R-01`
   - Show judges the explanation: *"No security action required for user asha performing 'view_balance'. Judgement rests on sufficient history."*

---

### Step 2: The Attack & Terminal Session Gate R11 (0:25 - 0:50)
1. **Simulate Adversary Injection:**
   - In the hardware injector panel, switch Device ID to `dev-hacker-kali` (Unfamiliar Device).
   - Switch Location to `London, UK` (Triggering **Geodesic Haversine Speed > 900 km/h**).
   - Switch Timestamp to `03:15 AM IST` (Deep night unusual hour, <2% historical probability).
2. **Execute Critical Takeover Action:** Click **"Update to attacker@mail.com"** (`change_email`).
3. **Observe Immediate Enforcement:**
   - The status banner instantly turns bright red: **HTTP 403: SESSION TERMINALLY REVOKED (R11)**.
   - The engine terminates the session instantly.
4. **Prove Invariant R11 (Terminal Refusal):**
   - Click **"View Balance"** or any other benign action.
   - The system immediately returns **HTTP 403 REFUSED (`refused_session_revoked`)**.
   - Explain to judges: *"Even if the attacker tries a benign action, the session gate permanently refuses execution and stops learning into Asha's baseline profile."*

---

### Step 3: SOC Analyst Command Center & Live Radar (0:50 - 1:15)
1. **Switch to SOC Dashboard:** `http://127.0.0.1:8000/`
2. **Show Live SSE Radar Feed:**
   - Notice the **LIVE RADAR** pulsing badge.
   - The revocation decision for Asha is already prepended at the very top of the table without requiring a page refresh!
3. **Open Decision Drilldown:** Click **"Inspect &rarr;"** on Asha's row:
   - Highlight **Plain-English Explanation**: Plain language for tier-1 SOC analysts with zero cryptic math.
   - Highlight **Signals Evaluated**: S1 (Unfamiliar Device), S2 (Implausible Speed 7,200 km/h), S3 (Unusual Hour), S4 (Sensitive Action).
4. **Trigger Google Gemini 2.5 AI Forensics (Stage C):**
   - Click the **"Generate Forensic Intel"** button.
   - Watch the AI synthesize tactical intelligence:
     - **Threat Level:** `CRITICAL THREAT`
     - **MITRE ATT&CK Mapping:** `T1078 (Valid Accounts)`, `T1539 (Steal Session Cookie)`, `T1566 (Phishing/Session Hijack)`.
     - **SOC Remediation Playbook:** Prescriptive next steps for incident responders.
   - Point out the **R9 Guard Invariant**: *"AI is strictly advisory. It enriches the investigation, but never triggers automated revokes alone."*

---

### Step 4: React 18 World Threat Map (1:15 - 1:35)
1. **Open React Threat Map:** `http://127.0.0.1:8000/react_app.html`
2. **Demonstrate Spatial ATO Chain:**
   - Select `ATO Takeover Chain` from the scenario dropdown and click **"Replay Scenario"**.
   - Watch the interactive global canvas trace the attack arc from Pune $\to$ London in real-time.
   - Show the dynamic policy sliders: sliding the speed threshold from `900 km/h` to `500 km/h` instantly synchronizes policy with the backend engine.

---

### Step 5: Deterministic Replay Sandbox & SHA-256 Ledger (1:35 - 2:00)
1. **Switch Back to SOC Studio & Click "Replay Sandbox (R10)":**
   - Run replay for `Elena Rostova (Account Takeover)`.
   - Point to the **Deterministic Replay Hash (SHA-256)**:
     - *"Every re-execution over the exact same event stream yields the identical cryptographic hash down to the bit."*
   - Show **Policy Diff Matrix**: Demonstrates candidate policy tuning against production rules with zero risk to live databases.
2. **Click "Audit Ledger (R8)":**
   - Show the green **"Chain Verified"** badge.
   - Every single decision, manual revocation, and 2FA challenge is cryptographically chained:
     $$\text{row\_hash}_n = \text{SHA-256}(\text{row\_hash}_{n-1} \parallel \text{actor} \parallel \text{action} \parallel \text{payload})$$
   - Any database tampering breaks the hash chain immediately.

---

## Key Invariant Cheat Sheet for Judges

| Rule / Invariant | Requirement | How IdentityGuard Proves It |
|---|---|---|
| **R1** | Strict 5-Field Ingress | Accepts ONLY `[timestamp, user, device, location, action]`. No IP or user agent required. |
| **R2** | Geodesic Haversine Speed | Great-circle math flag trips if speed exceeds `900.0 km/h`. |
| **R3** | Diurnal Circular Histogram | Smoothed circular hour distribution ($\sigma=1.0$ hr) detects unusual login times. |
| **R8** | Cryptographic Audit Ledger | SHA-256 hash-chained immutable audit trail with runtime verification. |
| **R9** | AI Strictly Advisory | Compile-time AST validator + runtime circuit breaker blocks ML from acting alone. |
| **R10** | Sandboxed Replay Determinism | Isolated in-memory replay engine computing bit-exact decision stream hashes. |
| **R11** | Terminal Session Revocation | Once revoked, all subsequent calls return HTTP 403 `SESSION_REVOKED` and stop baseline learning. |

---

## Quick Launch Command

```powershell
python run.py
```
- **Analyst SOC Studio:** `http://127.0.0.1:8000/`
- **React 18 Threat Map:** `http://127.0.0.1:8000/react_app.html`
- **Target Banking App:** `http://127.0.0.1:8000/bank_app.html`
- **Interactive OpenAPI Docs:** `http://127.0.0.1:8000/docs`
- **Automated Test Suite:** `python -m pytest tests/ -v` (66/66 Passing)
