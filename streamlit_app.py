import streamlit as st
import pandas as pd
import re, random

st.set_page_config(page_title="Komla Project - Balto AI Demo Suite", page_icon="🛡️", layout="wide")
st.title("Balto AI Demo Suite")
st.caption("Compliance Co-Pilot + Passion Project — Streamlit (no secrets, no external APIs)")

# -----------------------------
# Rich templates (from your Flask version)
# -----------------------------
QUESTIONNAIRE_TEMPLATES = {
    "vuln": ("Vulnerability Management",
             "We maintain an inventory of systems and run regular vulnerability scanning across infrastructure and applications. Findings are prioritized by severity and business impact. Standard timelines: Critical ≤ 7 days, High ≤ 14 days, Medium ≤ 30 days, Low ≤ 90 days. Exceptions require management approval and re-review. Penetration tests are conducted periodically and tracked in ticketing with leadership review."),
    "encryption": ("Encryption",
                   "Sensitive data is encrypted at rest (e.g., AES-256) and in transit (TLS 1.2+). We verify via configuration inspections, connection tests, and key management reviews (rotation, access controls). Evidence is retained for audit. See SOC 2 Security Policy (Section 4.2)."),
    "logging": ("Logging & Monitoring",
                "We collect and review logs using native cloud services (e.g., AWS CloudTrail/GuardDuty) and centralized observability. Daily reviews flag anomalies such as failed logins, privilege changes, public resource exposure, and logging tampering. Escalations follow documented SLAs."),
    "vendors": ("Third-Party Risk",
                "Vendors are assessed for certifications (e.g., SOC 2), MFA enforcement, policy currency, pentest posture, and encryption practices. Gaps require a remediation plan prior to processing data. Reviews are tracked in the risk register and re-assessed periodically.")
}

SEVERITY_SLA = {
    "Critical": "Remediate ≤ 7 days (hotfix now if exposure/exploit).",
    "High": "Remediate ≤ 30 days.",
    "Medium": "Remediate ≤ 90 days.",
    "Low": "Track/Backlog/Review."
}

def classify_log(line: str):
    txt = (line or "").strip()
    if not txt:
        return None
    if "S3 bucket" in txt and "made public" in txt:
        return ("Critical",
                "Potential customer data exposure.",
                "Remove public access now, check access logs, notify privacy/legal, start impact review.")
    if "IAM user" in txt and "AdminAccess" in txt:
        return ("High",
                "Least-privilege violation.",
                "Verify approval; revoke if unapproved; investigate account activity.")
    if "modified CloudTrail logging" in txt:
        return ("High",
                "Log integrity risk.",
                "Compare to baseline; revert if unapproved; restrict who can change CloudTrail; investigate user actions.")
    if "Unsuccessful login" in txt and "(8x" in txt:
        return ("Medium",
                "Likely brute-force attempt.",
                "Rate-limit/block IP; verify MFA; check if attempts spread; monitor closely.")
    if "Unsuccessful login" in txt and "(3x" in txt:
        return ("Low",
                "Likely user error.",
                "Confirm user; verify MFA; document and monitor for repetition.")
    if "EC2 instance" in txt and ("eu-" in txt or "ap-" in txt):
        return ("Medium",
                "Unapproved or unusual region usage.",
                "Verify change; stop if unapproved; investigate IAM role used.")
    if "TorIPCaller" in txt or "Tor" in txt:
        return ("High",
                "Recon from anonymized source.",
                "Review S3 policies; block public access; consider blocking Tor ranges; monitor closely.")
    return ("Low", "No rule matched; informational.", "Document and monitor.")

# -------- PII detection for Privacy QA --------
PII_PATTERNS = {
    "Email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "US Phone": re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "Credit Card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "Address-ish": re.compile(r"\b\d{1,5}\s+[A-Za-z0-9.\s]+,\s*[A-Za-z.\s]+,\s*[A-Z]{2}\s+\d{5}\b")
}

def luhn_check(num: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", num)]
    if len(digits) < 13:
        return False
    s, alt = 0, False
    for d in reversed(digits):
        if alt:
            d *= 2
            if d > 9: d -= 9
        s += d
        alt = not alt
    return s % 10 == 0

def redact(text: str):
    findings, redacted = [], text
    for label, pat in PII_PATTERNS.items():
        for m in list(pat.finditer(text)):
            val = m.group(0)
            if label == "Credit Card" and not luhn_check(val):
                continue
            findings.append((label, val))
            redacted = redacted.replace(val, f"[REDACTED-{label}]")
    return findings, redacted

# -------- Devotional Coach data --------
DEV_VERSES = {
    "anxious": [
        ("Philippians 4:6-7",
         "Do not be anxious about anything... and the peace of God... will guard your hearts and your minds in Christ Jesus."),
        ("Psalm 94:19",
         "When the cares of my heart are many, your consolations cheer my soul.")
    ],
    "lonely": [
        ("Isaiah 41:10",
         "Fear not, for I am with you... I will strengthen you, I will help you."),
        ("Psalm 27:10",
         "Though my father and mother forsake me, the Lord will receive me.")
    ],
    "weary": [
        ("Matthew 11:28",
         "Come to me, all who labor and are heavy laden, and I will give you rest."),
        ("Psalm 23:1-3",
         "The Lord is my shepherd... He restores my soul.")
    ],
    "grateful": [
        ("1 Thessalonians 5:18",
         "Give thanks in all circumstances; for this is the will of God in Christ Jesus for you."),
        ("Psalm 107:1",
         "Give thanks to the Lord, for he is good; his love endures forever.")
    ]
}
MUSIC_SUGGESTIONS = {
    "anxious": "Slow ambient pad at 60–70 BPM, soft piano melody.",
    "lonely": "Warm strings and gentle guitar, minimal percussion.",
    "weary": "Soft piano with airy pads, low-end rolled off.",
    "grateful": "Light piano arpeggios, subtle strings, 80–90 BPM."
}
def make_devotional(name: str, mood: str):
    verses = DEV_VERSES.get(mood, [("John 3:16",
                   "For God so loved the world that he gave his only Son...")])
    chosen = random.sample(verses, k=min(2, len(verses)))
    addressed = (name or "Friend")
    reflection = (
        f"{addressed}, here’s a reminder tailored to feeling {mood}. "
        "God sees you, and his word doesn’t minimize your pain — it meets you in it. "
        "Breathe slowly as you read; let the truth settle deeper than the thoughts that race."
    )
    prayer = ("Prayer: Father, quiet my mind and steady my heart. "
              "Help me receive your presence and trust your care, right now. Amen.")
    track = MUSIC_SUGGESTIONS.get(mood, "Soft ambient pad or gentle piano.")
    return chosen, reflection, prayer, track

# ---------------- UI ----------------
st.sidebar.header("Demos")
demo = st.sidebar.radio("Select a demo", [
    "Security Questionnaire Assistant",
    "Vendor Review Summarizer",
    "Daily Log Triage",
    "Call-Privacy QA",
    "Devotional Coach (Passion Project)"
])

# ---- Security Questionnaire Assistant ----
if demo == "Security Questionnaire Assistant":
    st.header("Security Questionnaire Assistant")

    col1, col2 = st.columns([2,1])
    with col1:
        q = st.text_area("Paste one question", height=140,
            placeholder="e.g., Do you encrypt sensitive data at rest and in transit?")
        if st.button("Draft Answer"):
            ql = (q or "").lower()
            if any(k in ql for k in ["vulnerability","patch","how quickly"]):
                title, ans = QUESTIONNAIRE_TEMPLATES["vuln"]
            elif any(k in ql for k in ["encrypt","at rest","in transit"]):
                title, ans = QUESTIONNAIRE_TEMPLATES["encryption"]
            elif any(k in ql for k in ["log","monitor","tools"]):
                title, ans = QUESTIONNAIRE_TEMPLATES["logging"]
            elif any(k in ql for k in ["third","vendor","supplier"]):
                title, ans = QUESTIONNAIRE_TEMPLATES["vendors"]
            else:
                title, ans = ("General",
                    "We follow documented security policies and control standards; specifics can be shared under NDA.")
            st.subheader(f"Section: {title}")
            st.write(ans)
    with col2:
        st.caption("Try examples:")
        st.code(
"""• Do you encrypt sensitive data at rest and in transit?
• Describe your vulnerability management timelines.
• What logging/monitoring do you perform (tools, cadence, reviews)?
• How do you assess third-party vendors before processing data?""", language="text")

# ---- Vendor Review Summarizer ----
elif demo == "Vendor Review Summarizer":
    st.header("Vendor Review Summarizer")
    col1, col2 = st.columns([2,1])
    with col1:
        txt = st.text_area("Paste vendor SOC 2/ISO excerpt or description", height=220,
            placeholder="Vendor holds SOC 2 Type II. Encryption at rest implemented. Backups are tested quarterly. No mention of annual penetration testing or incident response SLAs. MFA policy not specified.")
        if st.button("Summarize & Highlight Gaps"):
            gaps = []
            summary = "No explicit SOC 2 attestation found."
            if "soc 2" in txt.lower():
                summary = "SOC 2 attestation provided; controls described."
            if "mfa" not in txt.lower():
                gaps.append("MFA policy not stated — require MFA for workforce/admin accounts.")
            if "penetration" in txt.lower():
                if "annual" not in txt.lower():
                    gaps.append("Penetration testing mentioned but cadence unclear — require annual testing and reports.")
            else:
                gaps.append("No penetration testing mentioned — request recent report and remediation plan.")
            if "encrypt" not in txt.lower():
                gaps.append("Encryption practices not stated — confirm at rest/in transit, and key management.")
            if not ("policy" in txt.lower() and ("review" in txt.lower() or "annual" in txt.lower())):
                gaps.append("Policy review cadence unclear — commit to at least annual reviews.")
            st.subheader("Summary")
            st.write(summary)
            st.subheader("Gaps / Follow-ups")
            if gaps:
                for g in gaps: st.write(f"- {g}")
            else:
                st.write("No obvious gaps in this excerpt.")
    with col2:
        st.caption("Paste anything like:")
        st.code(
"""• 'SOC 2 Type II; backups quarterly; incident response not formalized'
• 'ISO 27001 certified; MFA enforced; pentest annually'
• 'Encryption in transit only; no key rotation mentioned'""", language="text")

# ---- Daily Log Triage ----
elif demo == "Daily Log Triage":
    st.header("Daily Log Triage")
    default = """06:10:23 - Unsuccessful login attempt from IP 203.0.113.45 (3x within 1 min)
07:45:51 - IAM user 'qa-auditor' granted AdminAccess policy
09:00:05 - S3 bucket 'call-recordings' made public
09:40:43 - Unsuccessful login attempt from IP 201.12.103.15 (8x within 1 min)
12:50:19 - User 'analyst-bob' modified CloudTrail logging config
Discovery:S3/TorIPCaller | ActionType=AWS_API_CALL | API=ListObjects | Service=s3.amazonaws.com"""
    logtext = st.text_area("Paste AWS-style events (one per line):", value=default, height=220)
    if st.button("Triage"):
        rows = []
        for line in logtext.splitlines():
            if not line.strip(): continue
            sev, why, action = classify_log(line)
            rows.append({
                "Event": line.strip(),
                "Severity": sev,
                "Why it matters": why,
                "Immediate Action": action,
                "SLA": SEVERITY_SLA[sev]
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True)

# ---- Call-Privacy QA ----
elif demo == "Call-Privacy QA":
    st.header("Call-Privacy QA")
    transcript = st.text_area("Paste a short transcript", height=220,
                              placeholder="Agent: Thanks for calling...\nCaller: My email is jane.doe@example.com and my SSN is 123-45-6789; card 4111 1111 1111 1111.")
    if st.button("Scan & Redact"):
        findings, redacted = redact(transcript or "")
        st.subheader("Likely PII Detected")
        if findings:
            for label, val in findings: st.write(f"- **{label}**: {val}")
        else:
            st.write("No obvious PII found.")
        st.subheader("Redacted Transcript")
        st.code(redacted or "", language="text")

# ---- Devotional Coach ----
elif demo == "Devotional Coach (Passion Project)":
    st.header("Devotional Coach (Passion Project)")
    col1, col2 = st.columns([2,1])
    with col1:
        name = st.text_input("Name (optional)", value="Komla")
        mood = st.selectbox("Mood", ["anxious", "lonely", "weary", "grateful"])
        if st.button("Create Devotional"):
            verses, reflection, prayer, track = make_devotional(name, mood)
            st.subheader(f"For {name or 'Friend'} — Feeling {mood.capitalize()}")
            st.markdown("**Scripture**")
            for ref, text in verses: st.write(f"- **{ref}** — {text}")
            st.markdown("**Reflection**"); st.write(reflection)
            st.markdown("**Prayer**"); st.write(prayer)
            st.markdown("**Music Bed Suggestion**"); st.write(track)
    with col2:
        st.caption("Idea: scale care with privacy-first tooling (no external APIs).")

