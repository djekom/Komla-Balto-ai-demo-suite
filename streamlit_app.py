
import streamlit as st
import re
import random
import pandas as pd

st.set_page_config(page_title="Balto AI Demo Suite", page_icon="🛡️", layout="wide")

st.title("Balto AI Demo Suite")
st.caption("Compliance Co‑Pilot + Passion Project — Streamlit (no secrets, no external APIs)")

st.sidebar.header("Demos")
demo = st.sidebar.radio("Select a demo", [
    "Security Questionnaire Assistant",
    "Vendor Review Summarizer",
    "Daily Log Triage",
    "Call-Privacy QA",
    "Devotional Coach (Passion Project)"
])

# ---------- Shared/Static Data ----------
QUESTIONNAIRE_TEMPLATES = {
    "vuln": ("Vulnerability Management",
             "We maintain an inventory of systems and run regular vulnerability scanning across infrastructure and applications. Findings are prioritized by severity and business impact. Standard timelines: Critical ≤ 7 days, High ≤ 14 days, Medium ≤ 30 days, Low ≤ 90 days. Exceptions require management approval and re-review."),
    "encryption": ("Encryption",
                   "Sensitive data is encrypted at rest (e.g., AES-256) and in transit (TLS 1.2+). We verify via configuration inspections, connection tests, and key management reviews."),
    "logging": ("Logging & Monitoring",
                "We collect and review logs using native cloud services (e.g., AWS CloudTrail/GuardDuty). Daily reviews flag anomalies such as failed logins, privilege changes, or resource exposure."),
    "vendors": ("Third‑Party Risk",
                "Vendors are assessed for certifications (e.g., SOC 2), MFA enforcement, policy currency, penetration testing posture, and encryption practices. Gaps require a remediation plan prior to processing data.")
}

SEVERITY_SLA = {
    "Critical": "Remediate ≤ 7 days (hotfix now if exposure/exploit).",
    "High": "Remediate ≤ 30 days.",
    "Medium": "Remediate ≤ 90 days.",
    "Low": "Track/Backlog/Review."
}

def classify_log(line: str):
    txt = line.strip()
    if not txt:
        return None
    if "S3 bucket" in txt and "made public" in txt:
        return ("Critical", "Potential customer data exposure.", "Remove public access now; check logs; notify privacy/legal.")
    if "IAM user" in txt and "AdminAccess" in txt:
        return ("High", "Least‑privilege violation.", "Verify approval; revoke if unapproved; investigate account activity.")
    if "Unsuccessful login" in txt and "(8x" in txt:
        return ("Medium", "Likely brute‑force attempt.", "Rate‑limit/block IP; verify MFA; monitor closely.")
    if "Unsuccessful login" in txt and "(3x" in txt:
        return ("Low", "Likely user error.", "Confirm user; verify MFA; document and monitor for repetition.")
    return ("Low", "No rule matched; informational.", "Document and monitor.")

PII_PATTERNS = {
    "Email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "US Phone": re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "Credit Card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
}

def redact(text: str):
    findings = []
    redacted = text
    for label, pat in PII_PATTERNS.items():
        for m in list(pat.finditer(text)):
            val = m.group(0)
            findings.append((label, val))
            redacted = redacted.replace(val, f"[REDACTED-{label}]")
    return findings, redacted

DEV_VERSES = {
    "anxious": [
        ("Philippians 4:6-7", "Do not be anxious about anything..."),
        ("Psalm 94:19", "When the cares of my heart are many, your consolations cheer my soul.")
    ],
    "lonely": [
        ("Isaiah 41:10", "Fear not, for I am with you..."),
        ("Psalm 27:10", "Though my father and mother forsake me, the Lord will receive me.")
    ]
}

MUSIC_SUGGESTIONS = {
    "anxious": "Slow ambient pad with soft piano.",
    "lonely": "Warm strings and gentle guitar."
}

def make_devotional(name: str, mood: str):
    verses = DEV_VERSES.get(mood, [("John 3:16", "For God so loved the world...")])
    chosen = random.sample(verses, k=min(2, len(verses)))
    reflection = f"{name or 'Friend'}, here’s encouragement for feeling {mood}."
    prayer = "Prayer: Father, quiet my mind and steady my heart. Amen."
    track = MUSIC_SUGGESTIONS.get(mood, "Soft ambient pad or gentle piano.")
    return chosen, reflection, prayer, track

# ---------- Pages ----------
if demo == "Security Questionnaire Assistant":
    st.header("Security Questionnaire Assistant")
    q = st.text_area("Paste one question", height=120)
    if st.button("Draft Answer"):
        ql = (q or "").lower()
        if "encrypt" in ql:
            title, ans = QUESTIONNAIRE_TEMPLATES["encryption"]
        elif "vulnerability" in ql:
            title, ans = QUESTIONNAIRE_TEMPLATES["vuln"]
        elif "log" in ql:
            title, ans = QUESTIONNAIRE_TEMPLATES["logging"]
        else:
            title, ans = ("General", "We follow documented security policies...")
        st.subheader(f"Section: {title}")
        st.write(ans)

elif demo == "Vendor Review Summarizer":
    st.header("Vendor Review Summarizer")
    txt = st.text_area("Paste vendor SOC 2/ISO excerpt", height=200)
    if st.button("Summarize"):
        gaps = []
        if "mfa" not in txt.lower():
            gaps.append("MFA policy not stated.")
        if "penetration" not in txt.lower():
            gaps.append("No penetration testing mentioned.")
        st.subheader("Gaps / Follow‑ups")
        st.write(gaps if gaps else "No obvious gaps.")

elif demo == "Daily Log Triage":
    st.header("Daily Log Triage")
    logtext = st.text_area("Paste AWS‑style events:", height=200)
    if st.button("Triage"):
        rows = []
        for line in logtext.splitlines():
            sev, why, action = classify_log(line)
            rows.append({"Event": line, "Severity": sev, "Why": why, "Action": action, "SLA": SEVERITY_SLA[sev]})
        st.dataframe(pd.DataFrame(rows))

elif demo == "Call-Privacy QA":
    st.header("Call‑Privacy QA")
    transcript = st.text_area("Paste transcript", height=200)
    if st.button("Scan & Redact"):
        findings, redacted = redact(transcript or "")
        st.subheader("Findings")
        st.write(findings)
        st.subheader("Redacted Transcript")
        st.code(redacted)

elif demo == "Devotional Coach (Passion Project)":
    st.header("Devotional Coach (Passion Project)")
    name = st.text_input("Name (optional)", value="Komla")
    mood = st.selectbox("Mood", ["anxious", "lonely"])
    if st.button("Create Devotional"):
        verses, reflection, prayer, track = make_devotional(name, mood)
        st.subheader(f"For {name or 'Friend'} — Feeling {mood.capitalize()}")
        for ref, text in verses:
            st.write(f"- **{ref}** — {text}")
        st.write(reflection)
        st.write(prayer)
        st.write(track)
