Komla Project Balto AI Demo Suite

This project is my submission for Balto’s AI Test. It showcases how AI can streamline compliance-critical workflows while also highlighting a personal “Passion Project.” The app is built in Python + Streamlit and is deployed on Streamlit Cloud for easy access.

 Features
Part I — Compliance Co-Pilot

Security Questionnaire Assistant
Paste in a question (e.g., “Do you encrypt sensitive data at rest and in transit?”).
The AI logic matches against compliance templates (SOC 2, PCI-DSS, etc.) and drafts a professional, evidence-backed answer.
Provides references like “See SOC 2 Security Policy, Section 4.2.”

Vendor Review Summarizer
Upload/paste vendor SOC 2 or ISO 27001 excerpts.
AI generates a structured summary and flags follow-up risks (e.g., no mention of annual penetration testing, MFA policy not stated).
Ensures consistent scoring across vendors.

Daily Log Triage
Paste AWS-style log events (CloudTrail, GuardDuty, IAM changes).
Tool classifies each event with:
Severity (Critical, High, Medium, Low)
Why it matters
Immediate Action
SLA for remediation
Example: S3 bucket 'call-recordings' made public → Critical (customer data exposure).

Call-Privacy QA
Paste a transcript (e.g., call audio turned to text).
Detects PII such as emails, SSNs, phone numbers, credit cards.
Produces a redacted transcript for compliance with HIPAA/GDPR.


Part II — Passion Project: Devotional Coach
Inspired by my YouTube channel Speak, Lord! which creates peaceful, Christ-centered messages.
Select a mood (anxious, lonely, weary, grateful).
App returns:
Scriptures tailored to that mood
Reflection (empathetic, practical insight)
Prayer
Music suggestion for background
Demonstrates how AI can scale encouragement and deliver personalized, real-time comfort.

How to Run
Local (optional)
pip install -r requirements.txt
streamlit run streamlit_app.py


Visit http://localhost:8501

Live Demo
Tech Stack
Python 3.9+
Streamlit (UI framework)
pandas (log/event table formatting)
No external APIs or sensitive data used. All logic is local and privacy-first.

Notes
The Compliance Co-Pilot mirrors daily tasks of a Jr. Security Compliance Analyst: log triage, vendor reviews, customer questionnaires, privacy checks.
The Devotional Coach shows how AI can extend creativity and care into personal projects.

