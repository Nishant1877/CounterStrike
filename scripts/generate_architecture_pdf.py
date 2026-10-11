"""
IdentityGuard (A-03) Master Architecture & Implementation Blueprint Generator.
Generates an executive-grade, beautifully formatted PDF document.
"""

import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and display total page count."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        if self._pageNumber == 1:
            # Skip header/footer on cover/first page
            return

        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running Header
        self.drawString(54, 11 * inch - 36, "IDENTITYGUARD (A-03) | SYSTEM ARCHITECTURE & IMPLEMENTATION BLUEPRINT")
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.5)
        self.line(54, 11 * inch - 42, 8.5 * inch - 54, 11 * inch - 42)

        # Running Footer
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * inch - 54, 36, page_text)
        self.drawString(54, 36, "CONFIDENTIAL - HACKATHON MASTER DOCUMENT | DOMAIN 2: AI SYSTEMS & INFRASTRUCTURE")
        self.line(54, 46, 8.5 * inch - 54, 46)
        self.restoreState()


def build_pdf(filename: str):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Custom typography styles
    primary_color = colors.HexColor("#0f172a")    # Deep Navy
    accent_color = colors.HexColor("#2563eb")     # Vivid Blue
    slate_dark = colors.HexColor("#1e293b")
    text_muted = colors.HexColor("#475569")
    bg_light = colors.HexColor("#f8fafc")
    border_color = colors.HexColor("#cbd5e1")

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=primary_color,
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=accent_color,
        spaceAfter=15
    )

    h1_style = ParagraphStyle(
        'Header1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=primary_color,
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Header2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=accent_color,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=slate_dark,
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        'Bullet',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=slate_dark,
        leftIndent=12,
        firstLineIndent=-8,
        spaceAfter=3
    )

    code_style = ParagraphStyle(
        'CodeSnippet',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderPadding=4,
        spaceAfter=6
    )

    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.white
    )

    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=10,
        textColor=slate_dark
    )

    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=10,
        textColor=slate_dark
    )

    story = []

    # -------------------------------------------------------------
    # COVER / HEADER BANNER
    # -------------------------------------------------------------
    story.append(Paragraph("IdentityGuard (A-03)", title_style))
    story.append(Paragraph("Session Risk & Account-Takeover Detection | System Architecture & 12-Hour Execution Blueprint", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=accent_color, spaceBefore=0, spaceAfter=12))

    banner_data = [
        [
            Paragraph("<b>Domain:</b> Domain 2 — AI Systems & Infrastructure", table_cell_style),
            Paragraph("<b>Target Timeframe:</b> 12-Hour Hackathon Execution", table_cell_style),
            Paragraph("<b>Current Status:</b> Stage 1 Complete & Verified (Commit 3829939)", table_cell_style)
        ]
    ]
    t_banner = Table(banner_data, colWidths=[2.3 * inch, 2.3 * inch, 2.6 * inch])
    t_banner.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#eff6ff")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#bfdbfe")),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(t_banner)
    story.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # 1. EXECUTIVE SUMMARY & PROBLEM STATEMENT ANALYSIS
    # -------------------------------------------------------------
    story.append(Paragraph("1. Problem Statement & Hackathon Winning Strategy", h1_style))
    story.append(Paragraph(
        "<b>The Threat Model:</b> Account Takeover (ATO) commonly starts when an intruder logs in from an unfamiliar device "
        "and geography, swiftly executing sensitive actions such as changing email credentials or requesting balance transfers. "
        "Standard heuristic engines trigger severe false alarms on legitimate travelers, remote workers, or device upgrades. "
        "Vague alerts (e.g., <i>'Suspicious Login'</i>) fail operational analysts.",
        body_style
    ))
    story.append(Paragraph(
        "<b>The Strict Spec Invariants:</b> The specification establishes definitive guardrails that separate winning solutions from disqualified entries:",
        body_style
    ))
    story.append(Paragraph("• <b>The 5-Field Ingress Boundary (R1):</b> Input is strictly constrained to <code>[timestamp, user, device_id, location_label, action]</code>. No IP addresses, ASN numbers, device fingerprints, or client session IDs are assumed.", bullet_style))
    story.append(Paragraph("• <b>AI Is Advisor Only (R9):</b> Action-sequence AI models provide contextual probability scores, but are <b>strictly forbidden</b> from executing actions alone. An architectural compile-time and runtime circuit breaker enforces this.", bullet_style))
    story.append(Paragraph("• <b>Data Honesty over Hallucination (R4, R5, R7):</b> Missing locations or sparse user histories produce explicit <code>not_evaluable</code> signal states and <code>limited</code> evidence banners, never silent guesses.", bullet_style))
    story.append(Paragraph("• <b>100% Deterministic Replay (R10):</b> Both live streaming and analyst replays run through the exact same pure pipeline function, validated via SHA-256 cryptographic digest equality.", bullet_style))
    story.append(Paragraph("• <b>Terminal Revocation Gate (R11):</b> Once a session is revoked, all subsequent actions are immediately refused with HTTP 403 <code>SESSION_REVOKED</code>, blocked from profile learning.", bullet_style))

    story.append(Spacer(1, 6))

    # -------------------------------------------------------------
    # 2. REQUIREMENTS MATRIX (R1 - R11)
    # -------------------------------------------------------------
    story.append(Paragraph("2. Official Requirements Compliance Matrix (R1 to R11)", h1_style))

    req_headers = [Paragraph("Req", table_header_style), Paragraph("Official Requirement", table_header_style), Paragraph("Architectural Solution", table_header_style), Paragraph("Status", table_header_style)]
    req_rows = [
        req_headers,
        [Paragraph("<b>R1</b>", table_cell_bold), Paragraph("Receive 5-field events (ts, user, device, loc, action)", table_cell_style), Paragraph("Pydantic V2 raw schema + ISO UTC normalizer", table_cell_style), Paragraph("<font color='#16a34a'><b>VERIFIED</b></font>", table_cell_style)],
        [Paragraph("<b>R2</b>", table_cell_bold), Paragraph("Learn each user's usual pattern from earlier events", table_cell_style), Paragraph("Point-in-time Profile Engine (smoothed 24h histogram, device state)", table_cell_style), Paragraph("<font color='#16a34a'><b>VERIFIED</b></font>", table_cell_style)],
        [Paragraph("<b>R3</b>", table_cell_bold), Paragraph("Detect & explain 4 risk signals (S1-S4) with values & reasons", table_cell_style), Paragraph("Modular detectors returning standardized SignalResult contracts", table_cell_style), Paragraph("<font color='#16a34a'><b>VERIFIED</b></font>", table_cell_style)],
        [Paragraph("<b>R4</b>", table_cell_bold), Paragraph("Handle sparse history gracefully", table_cell_style), Paragraph("Evidence tiers (none/limited/sufficient); fallback to analyst review", table_cell_style), Paragraph("<font color='#16a34a'><b>VERIFIED</b></font>", table_cell_style)],
        [Paragraph("<b>R5</b>", table_cell_bold), Paragraph("Handle unknown location labels without guessing", table_cell_style), Paragraph("Location alias DB; unresolvable marked UNKNOWN; S2 not_evaluable", table_cell_style), Paragraph("<font color='#16a34a'><b>VERIFIED</b></font>", table_cell_style)],
        [Paragraph("<b>R6</b>", table_cell_bold), Paragraph("Handle out-of-order, late, tied and duplicate timestamps", table_cell_style), Paragraph("OrderingHandler with SHA-256 deduplication and late event tracking", table_cell_style), Paragraph("<font color='#16a34a'><b>VERIFIED</b></font>", table_cell_style)],
        [Paragraph("<b>R7</b>", table_cell_bold), Paragraph("State when judgement rests on limited information", table_cell_style), Paragraph("Prominent evidence statement banner in all decision outputs", table_cell_style), Paragraph("<font color='#2563eb'><b>STAGE 2</b></font>", table_cell_style)],
        [Paragraph("<b>R8</b>", table_cell_bold), Paragraph("Apply configurable responses via explicit readable rules", table_cell_style), Paragraph("YAML Rule AST Engine with 4 outcomes and strict precedence", table_cell_style), Paragraph("<font color='#2563eb'><b>STAGE 2</b></font>", table_cell_style)],
        [Paragraph("<b>R9</b>", table_cell_bold), Paragraph("AI advises action sequences; cannot trigger response alone", table_cell_style), Paragraph("Markov sequence model + compile-time & runtime circuit breaker", table_cell_style), Paragraph("<font color='#2563eb'><b>STAGE 2</b></font>", table_cell_style)],
        [Paragraph("<b>R10</b>", table_cell_bold), Paragraph("Analyst replay of stored events with signals & responses", table_cell_style), Paragraph("Sandboxed Replay Runner with side-by-side diff & SHA-256 hash", table_cell_style), Paragraph("<font color='#f59e0b'><b>STAGE 4</b></font>", table_cell_style)],
        [Paragraph("<b>R11</b>", table_cell_bold), Paragraph("Revoked session must be refused all further actions", table_cell_style), Paragraph("Session Gate: atomic HTTP 403 refusal at ingress and API", table_cell_style), Paragraph("<font color='#f59e0b'><b>STAGE 3</b></font>", table_cell_style)],
    ]

    t_req = Table(req_rows, colWidths=[0.5 * inch, 2.7 * inch, 3.2 * inch, 0.8 * inch])
    t_req.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), primary_color),
        ('GRID', (0, 0), (-1, -1), 0.5, border_color),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, bg_light]),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(t_req)

    story.append(PageBreak())

    # -------------------------------------------------------------
    # 3. END-TO-END ARCHITECTURE & DATA FLOW
    # -------------------------------------------------------------
    story.append(Paragraph("3. System Architecture & Processing Pipeline", h1_style))
    story.append(Paragraph(
        "IdentityGuard is structured in a clean, decoupled architecture. The core detection and decision logic is isolated "
        "in a pure, zero-dependency Python package (<code>core/</code>) that does not import web frameworks or databases. "
        "This ensures identical determinism across live ingestion, automated tests, and offline replays.",
        body_style
    ))

    arch_data = [
        [Paragraph("<b>Pipeline Stage</b>", table_header_style), Paragraph("<b>Functionality & Invariant</b>", table_header_style), Paragraph("<b>Component</b>", table_header_style)],
        [Paragraph("1. Ingestion & Gate", table_cell_bold), Paragraph("Validates 5-field contract. Enforces <b>R11 Revocation Gate</b> immediately. Revoked sessions receive HTTP 403 without touching profile state.", table_cell_style), Paragraph("<code>core/normalize.py<br/>store/session_gate.py</code>", table_cell_style)],
        [Paragraph("2. Ordering Handler", table_cell_bold), Paragraph("Identifies on-time, late, duplicate (SHA-256 deduplicated), and future clock-skew events. Maintains arrival sequence.", table_cell_style), Paragraph("<code>core/ordering.py</code>", table_cell_style)],
        [Paragraph("3. Point-in-Time Profile", table_cell_bold), Paragraph("Constructs user pattern using only historical events where <i>T < T_current</i>. Evaluates evidence level (none, limited, sufficient).", table_cell_style), Paragraph("<code>core/profile.py</code>", table_cell_style)],
        [Paragraph("4. Signal Engine (S1-S4)", table_cell_bold), Paragraph("Evaluates measured facts against thresholds. Outputs standardized <code>SignalResult</code> with human-readable rationale.", table_cell_style), Paragraph("<code>core/signals/</code>", table_cell_style)],
        [Paragraph("5. AI Advisory Module", table_cell_bold), Paragraph("Scores action transition sequences via Markov model. Outputs advisory context. Evaluated behind strict runtime guard (R9).", table_cell_style), Paragraph("<code>core/advisory/markov.py<br/>core/advisory/guard.py</code>", table_cell_style)],
        [Paragraph("6. Rule Engine", table_cell_bold), Paragraph("Evaluates declarative YAML rules. Enforces response precedence: <code>revoke > step_up > analyst_review > no_action</code>.", table_cell_style), Paragraph("<code>core/rules/dsl.py<br/>core/rules/engine.py</code>", table_cell_style)],
        [Paragraph("7. Replay & Audit", table_cell_bold), Paragraph("Sandboxed execution of events against arbitrary rules. Generates cryptographic SHA-256 hash and side-by-side diff matrices.", table_cell_style), Paragraph("<code>replay/runner.py<br/>store/audit.py</code>", table_cell_style)],
    ]
    t_arch = Table(arch_data, colWidths=[1.6 * inch, 3.8 * inch, 1.8 * inch])
    t_arch.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), accent_color),
        ('GRID', (0, 0), (-1, -1), 0.5, border_color),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, bg_light]),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(t_arch)

    story.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # 4. SIGNAL SPECIFICATIONS & MATHEMATICAL MODELS
    # -------------------------------------------------------------
    story.append(Paragraph("4. Signal Catalog & Mathematical Formulations", h1_style))

    story.append(Paragraph("<b>Signal S1: Unfamiliar Device</b>", h2_style))
    story.append(Paragraph(
        "Compares <code>device_id</code> against the user's historical devices. The first-ever device registered by a user is established as baseline (not unfamiliar). "
        "A device transitions from <code>unfamiliar</code> to <code>known</code> after 3 incident-free logins or verified step-up challenges.",
        body_style
    ))

    story.append(Paragraph("<b>Signal S2: Implausible Location Change (Haversine Geodesic Speed)</b>", h2_style))
    story.append(Paragraph(
        "Calculates Great-Circle planetary distance between current and last known resolvable event locations:<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;<i>d = 2R · arcsin(√(sin²(Δφ/2) + cos(φ₁)cos(φ₂)sin²(Δλ/2)))</i><br/>"
        "Implied velocity: <i>v = d / Δt</i>. Triggers if <i>v > 900 km/h</i> (airliner speed limit) AND <i>d > 50 km</i>. "
        "Plausible commercial flights (e.g., Pune to London in 10 hours = 720 km/h) evaluate to <code>not_triggered</code>. "
        "Unresolvable or missing locations evaluate to <code>not_evaluable</code> without guessing.",
        body_style
    ))

    story.append(Paragraph("<b>Signal S3: Unusual Activity Hour (Diurnal Density)</b>", h2_style))
    story.append(Paragraph(
        "Constructs a 24-bin histogram in the user's home timezone, smoothed across circular adjacent hours:<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;<i>P(h) = 0.25 · P((h-1) mod 24) + 0.5 · P(h) + 0.25 · P((h+1) mod 24)</i><br/>"
        "Triggers if <i>P(h) < 0.02</i> (less than 2% of activity) AND the user has at least 5 active days. Users with fewer than 5 active days are marked <code>not_evaluable</code>.",
        body_style
    ))

    story.append(Paragraph("<b>Signal S4: Sensitive Action Post-Login</b>", h2_style))
    story.append(Paragraph(
        "Correlates sensitive operations (<code>change_email</code>, <code>change_password</code>, <code>request_transfer</code>) occurring within 30 minutes of a login initiated from an unfamiliar device.",
        body_style
    ))

    story.append(PageBreak())

    # -------------------------------------------------------------
    # 5. AI ADVISORY CORE & THE RUNTIME GUARD (R9)
    # -------------------------------------------------------------
    story.append(Paragraph("5. AI Core: Blended Markov Sequence Model & Circuit Breaker (R9)", h1_style))
    story.append(Paragraph(
        "<b>Model Architecture:</b> A first-order Markov Transition Matrix models the sequential likelihood of action tokens. "
        "To solve the cold-start problem, transition probabilities are dynamically blended between the user's personal counts "
        "and a global population prior matrix:",
        body_style
    ))
    story.append(Paragraph(
        "&nbsp;&nbsp;&nbsp;&nbsp;<i>P_blended(a_t | a_{t-1}) = λ · P_{user}(a_t | a_{t-1}) + (1 - λ) · P_{global}(a_t | a_{t-1})</i><br/>"
        "where <i>λ = min(1.0, N_{sessions} / 20)</i>.",
        body_style
    ))
    story.append(Paragraph(
        "<b>Strict Architectural Enforcement (The Dual Anti-Bypass Guard):</b>",
        body_style
    ))
    story.append(Paragraph("1. <b>Compile-Time AST Verification:</b> The rule parser inspects all condition nodes. Any rule whose conditions reference only the AI advisory is rejected before activation.", bullet_style))
    story.append(Paragraph("2. <b>Runtime Circuit Breaker:</b> During evaluation, if a rule match occurred solely due to the AI advisory without corroboration from at least one deterministic signal (S1-S4), the engine forces the response to <code>no_action</code> and records an audit suppression flag.", bullet_style))

    story.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # 6. DECLARATIVE RULE ENGINE & PRECEDENCE (R8)
    # -------------------------------------------------------------
    story.append(Paragraph("6. Declarative Rule Engine & Precedence (R8)", h1_style))
    story.append(Paragraph(
        "Rules are defined in human-readable YAML format. Analysts can inspect, test, and hot-reload rules without code changes.",
        body_style
    ))

    sample_yaml = """rules:
  - id: R-06
    name: "Sensitive action after unfamiliar login + second risk signal"
    when:
      all:
        - signal: sensitive_after_unfamiliar_login
          is: triggered
        - any:
            - signal: implausible_location_change
              is: triggered
            - signal: unusual_hour
              is: triggered
    requires_evidence: sufficient
    if_evidence_lower: analyst_review
    response: revoke
    also_open_review: true"""
    story.append(Paragraph(sample_yaml.replace('\n', '<br/>').replace(' ', '&nbsp;'), code_style))

    story.append(Paragraph(
        "<b>Precedence Order:</b> <code>revoke</code> (1st) &gt; <code>step_up</code> (2nd) &gt; <code>analyst_review</code> (3rd) &gt; <code>no_action</code> (4th).<br/>"
        "<b>Evidence-Aware Fallbacks:</b> If rule R-06 matches but history is sparse (<code>limited</code> evidence), the response is automatically downgraded from <code>revoke</code> to <code>analyst_review</code>.",
        body_style
    ))

    story.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # 7. DETERMINISTIC REPLAY & AUDIT LEDGER (R10)
    # -------------------------------------------------------------
    story.append(Paragraph("7. Replay Workbench & Cryptographic Audit Ledger (R10)", h1_style))
    story.append(Paragraph(
        "<b>Sandboxed Replay:</b> Analysts can re-run historical event batches against modified rules or thresholds. "
        "Replay uses an isolated ephemeral database and executes through the exact same <code>core/pipeline.py</code> code path. "
        "Determinism is cryptographically guaranteed by hashing decision outcomes (SHA-256).",
        body_style
    ))
    story.append(Paragraph(
        "<b>Hash-Chained Audit Trail:</b> Every state transition, manual analyst override, or rule update appends a row to an immutable audit table where <i>row_hash = SHA256(prev_hash + row_data)</i>, guaranteeing tamper-evidence.",
        body_style
    ))

    story.append(PageBreak())

    # -------------------------------------------------------------
    # 8. THE 12-HOUR HACKATHON COMMIT BLUEPRINT
    # -------------------------------------------------------------
    story.append(Paragraph("8. 12-Hour Staged Execution Plan & Git Commit Blueprint", h1_style))
    story.append(Paragraph(
        "To ensure zero mistakes, complete reproducibility, and disciplined progress, the project is divided into 6 distinct stages. "
        "Each stage compiles, passes test suites, and corresponds to an atomic commit.",
        body_style
    ))

    commit_data = [
        [Paragraph("Stage / Time", table_header_style), Paragraph("Git Commit Message", table_header_style), Paragraph("Deliverables & Validation Checkpoint", table_header_style)],
        [Paragraph("<b>Stage 1</b><br/>(Hours 0-2.5)", table_cell_bold), Paragraph("<code>feat(core): 5-field event contracts, normalizer, signals (S1-S4) & profile builder</code>", table_cell_style), Paragraph("<b>COMPLETED & COMMITTED (Commit 3829939).</b> 10 unit tests pass on geodesic speed, timezone smoothing, and 5-field schema validation.", table_cell_style)],
        [Paragraph("<b>Stage 2</b><br/>(Hours 2.5-4.5)", table_cell_bold), Paragraph("<code>feat(rules): readable YAML rule engine, precedence resolver & AI advisory guard (R8, R9)</code>", table_cell_style), Paragraph("Markov sequence model, YAML AST parser, precedence evaluator, compile/runtime AI guard, explanation templates.", table_cell_style)],
        [Paragraph("<b>Stage 3</b><br/>(Hours 4.5-6.5)", table_cell_bold), Paragraph("<code>feat(api): FastAPI endpoints, session gate enforcement (R11) and audit ledger</code>", table_cell_style), Paragraph("SQLite models, session state machine, atomic revocation gate returning HTTP 403, hash-chained audit logging, REST routes.", table_cell_style)],
        [Paragraph("<b>Stage 4</b><br/>(Hours 6.5-8.5)", table_cell_bold), Paragraph("<code>feat(replay): deterministic sandboxed replay engine and diff comparator (R10)</code>", table_cell_style), Paragraph("Replay runner in sandbox memory DB, side-by-side diff matrix, SHA-256 decision hash invariance verification.", table_cell_style)],
        [Paragraph("<b>Stage 5</b><br/>(Hours 8.5-10.5)", table_cell_bold), Paragraph("<code>feat(ui): glassmorphic analyst dashboard, replay workbench & target banking app</code>", table_cell_style), Paragraph("Analyst SOC dashboard, real-time live event feed, 24-hr circular histogram, Replay diff workbench, Target banking demo portal.", table_cell_style)],
        [Paragraph("<b>Stage 6</b><br/>(Hours 10.5-12.0)", table_cell_bold), Paragraph("<code>feat(demo): golden test fixtures, acceptance suite (R1-R11) and 1-click launcher</code>", table_cell_style), Paragraph("11 official acceptance tests (Section 18.1), 12 scenario test cases (Section 18.2), demo seeder, <code>run.py</code> 1-click boot.", table_cell_style)],
    ]

    t_commits = Table(commit_data, colWidths=[1.1 * inch, 2.7 * inch, 3.4 * inch])
    t_commits.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), primary_color),
        ('GRID', (0, 0), (-1, -1), 0.5, border_color),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, bg_light]),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(t_commits)

    story.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # 9. FRONTEND & TARGET BANKING DEMO APP
    # -------------------------------------------------------------
    story.append(Paragraph("9. Frontend Architecture: Analyst SOC & Target Banking Portal", h1_style))
    story.append(Paragraph(
        "<b>Zero-Friction Serving Architecture:</b> The frontend is built as a responsive Single-Page Application (SPA) served directly "
        "by FastAPI static endpoints using modern ES modules, Tailwind CSS, and Chart.js. This avoids npm/bundler friction and ensures judges can run the demo immediately with zero configuration.",
        body_style
    ))
    story.append(Paragraph(
        "<b>Core UI Modules:</b>",
        body_style
    ))
    story.append(Paragraph("• <b>Incident Command Stream:</b> Real-time event ticker displaying user, location, action, risk status, and latency.", bullet_style))
    story.append(Paragraph("• <b>Signal Inspection Radar:</b> Detailed breakdown cards showing measured values, references, thresholds, and clear explanations.", bullet_style))
    story.append(Paragraph("• <b>User Profile Explorer:</b> Visual 24-hour circular activity chart, home timezone indicator, and trusted device tree.", bullet_style))
    story.append(Paragraph("• <b>Replay Workbench:</b> Interactive slider comparing historical vs. alternate rule sets with live diff highlights.", bullet_style))
    story.append(Paragraph("• <b>Live Target Banking Portal:</b> Embedded consumer banking app allowing judges to click 'Login', 'Transfer', and 'Change Email'. When malicious behavior triggers, the portal instantly locks out with a prominent HTTP 403 modal.", bullet_style))

    story.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # 10. 3-MINUTE WINNING DEMO SCRIPT
    # -------------------------------------------------------------
    story.append(Paragraph("10. The 3-Minute Hackathon Winning Demo Script", h1_style))
    story.append(Paragraph("1. <b>Minute 0-1 (Legitimate User & False Alarm Defense):</b> Show Asha logging in from Pune. Showcase her clean 24-hour histogram. Trigger a 10-hour flight to London: speed is 720 km/h (<900 km/h). IdentityGuard records S5 but produces <code>no_action</code>. Zero false alarms.", bullet_style))
    story.append(Paragraph("2. <b>Minute 1-2 (The Attack & Terminal Enforcement):</b> Attacker logs in from Dev-X in London 30 mins after Pune and clicks 'Change Email'. R-06 fires instantly. Show the banking app locking out immediately with HTTP 403 <code>SESSION_REVOKED</code>. Subsequent actions are blocked.", bullet_style))
    story.append(Paragraph("3. <b>Minute 2-3 (Honest Uncertainty & Deterministic Replay):</b> Show a sparse-history user (3 past events): R-06 auto-downgrades to <code>analyst_review</code> with a clear caveat. Open the Replay Workbench, modify thresholds, run replay, and demonstrate matching cryptographic SHA-256 hashes.", bullet_style))

    # Build document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Successfully generated PDF: {filename}")


if __name__ == "__main__":
    output_path = r"d:\Vortex 3.0\docs\IdentityGuard_Architecture_and_Execution_Plan.pdf"
    build_pdf(output_path)
