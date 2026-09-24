# AI & API Security Portfolio

**Beatrice Mwangi** · Application Security / DevSecOps Engineer · [LinkedIn](https://www.linkedin.com/in/beatrice-mwangi-948928120)

Two hands-on security assessments of LLM-powered systems, each with a written report, working remediation code, and regression tests that reproduce every finding. A GitHub Actions pipeline runs the tests and a SAST scan (Bandit) on every push.

| # | Project | Focus | Frameworks |
|---|---|---|---|
| 01 | [LLM API Security Audit](01-llm-api-security-audit/) | API input handling, system-prompt leakage, resource exhaustion | OWASP API Security Top 10 (2023), OWASP Top 10 for LLM Apps (2025) |
| 02 | [AI Red Team: RAG Poisoning & Agent Abuse](02-ai-red-team-rag-assessment/) | Indirect prompt injection, data exfiltration, jailbreaks, excessive agency | MITRE ATLAS, OWASP Top 10 for LLM Apps (2025) |

## How each project is structured

```
report (README.md)  ->  findings with severity, impact, proof of concept
app/ or rag_guard/  ->  remediation code (Python, FastAPI, Pydantic v2)
tests/              ->  one regression test per finding, so fixes stay fixed
```

## Run locally

```bash
pip install -r requirements.txt
cd 01-llm-api-security-audit && pytest -q
cd ../02-ai-red-team-rag-assessment && pytest -q
```

## Scope and ethics

These are **independent lab assessments**. The target systems are mock applications I designed to mirror common enterprise patterns (FastAPI + LangChain-style RAG + tool-calling agent). No real organisation, product or user data was tested. Payloads are documented at the level needed to explain each finding and verify the fix.

## About me

Application Security Engineer focused on secure SDLC, API security, threat modelling and CI/CD security automation. Certifications: CASP, CDP, CTMP, CCNSE, CCSE, CSSE, CSSA. Former U.S. CISA ICS security fellow. Based in Nairobi, open to relocation within the EU.
