# 🔬 AI API Testing Framework

> **Autonomous multi-agent API testing powered by LLMs** — functional testing, OWASP security scanning, and HTML/JSON reports, all from a single spec file.

---

## Abstract

This project presents an AI-agent-based API testing framework designed to automate functional and security testing of web APIs. The framework uses specialized agents to analyze API specifications, generate intelligent test cases, execute requests, validate outputs, and identify potential vulnerabilities. Unlike traditional API testing tools that depend heavily on manual scripting, this framework leverages AI to understand endpoint behavior, create edge-case scenarios, and produce detailed reports with remediation guidance. The system improves testing efficiency, reduces human effort, and enhances coverage for both functionality and security. The framework can be applied in secure software development pipelines to support continuous API validation and vulnerability assessment.

---

## Architecture

```
ai-api-testing-framework/
│
├── agents/
│   ├── api_understanding_agent.py   # Parses + LLM-enriches API specs
│   ├── test_generation_agent.py     # Positive, negative, fuzz & LLM test cases
│   ├── execution_agent.py           # Async HTTP request dispatcher
│   ├── validation_agent.py          # Schema, status, data-safety checks
│   ├── security_agent.py            # OWASP API Top 10 analysis
│   └── reporting_agent.py           # HTML + JSON report generation
│
├── core/
│   ├── parser.py       # OpenAPI 3.x / Swagger 2.x parser
│   ├── executor.py     # Async HTTP client with retry + concurrency
│   ├── validator.py    # Response validation (schema, sensitive data, errors)
│   └── logger.py       # Rich console + file logging
│
├── static/
│   └── index.html      # Dashboard UI (dark cyber aesthetic)
│
├── samples/
│   └── petstore.yaml   # Sample OpenAPI spec for testing
│
├── tests/
│   └── test_framework.py  # pytest unit tests
│
├── app.py              # FastAPI server
├── run.py              # CLI runner
└── requirements.txt
```

---

## Agent Pipeline

```
User Input (spec file / URL)
        │
        ▼
┌─────────────────────┐
│  API Understanding  │  ← Parses OpenAPI/Swagger + LLM endpoint enrichment
│       Agent         │
└────────┬────────────┘
         │ APISpec
         ▼
┌─────────────────────┐
│  Test Generation    │  ← Positive, negative, fuzz, LLM-creative test cases
│       Agent         │
└────────┬────────────┘
         │ List[TestCase]
         ▼
┌─────────────────────┐
│  Execution Agent    │  ← Async concurrent HTTP requests with retry
└────────┬────────────┘
         │ List[ExecutionResult]
         ▼
┌─────────────────────┐
│  Validation Agent   │  ← Status, schema, sensitive data, verbose errors
└────────┬────────────┘
         │ List[ValidatedResult]
         ▼
┌─────────────────────┐
│  Security Agent     │  ← OWASP API Top 10 (rule-based + LLM deep scan)
└────────┬────────────┘
         │ List[SecurityFinding]
         ▼
┌─────────────────────┐
│  Reporting Agent    │  ← HTML dashboard + JSON export
└─────────────────────┘
```

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure environment
```bash
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

### 3. CLI usage
```bash
# Test the sample Petstore API
python run.py --spec samples/petstore.yaml

# With custom base URL and auth
python run.py --spec samples/petstore.yaml \
  --base-url https://petstore3.swagger.io/api/v3 \
  --auth "Bearer YOUR_TOKEN"
```

### 4. Web dashboard
```bash
python app.py
# Open http://localhost:8000
```

### 5. Run unit tests
```bash
pytest tests/ -v
```

---

## Features

| Feature | Details |
|---|---|
| **Spec Parsing** | OpenAPI 3.x and Swagger 2.x (YAML/JSON) |
| **Test Generation** | Positive, negative, edge-case, fuzz, LLM-creative |
| **Security Payloads** | SQLi, XSS, path traversal, oversized inputs, special chars |
| **OWASP Coverage** | API1–API10 (broken auth, BOLA, rate-limiting, injections…) |
| **Async Execution** | Concurrent requests with retry and timeout |
| **Validation** | Status codes, JSON schema, sensitive data, verbose errors |
| **LLM Integration** | OpenAI GPT-4o for enrichment, creative tests, deep security scan |
| **Reports** | HTML (dark themed dashboard) + JSON |
| **Dashboard UI** | Real-time pipeline progress, filterable results, security panel |
| **CLI** | Rich console output with summary tables |

---

## Test Case Categories

- **Positive (functional)** — Happy-path with valid inputs
- **Negative** — Missing required fields, wrong types, no auth
- **Security/Fuzz** — SQL injection, XSS, path traversal, oversized payloads
- **Edge** — LLM-generated creative boundary conditions

---

## OWASP API Security Top 10 Coverage

| ID | Vulnerability | Detection Method |
|---|---|---|
| API1 | Broken Object Level Authorization | Resource endpoint 200 check |
| API2 | Broken Authentication | Unauthenticated request analysis |
| API3 | Broken Object Property Level Authorization | LLM scan |
| API4 | Unrestricted Resource Consumption | Rate-limit header detection |
| API5 | Broken Function Level Authorization | LLM scan |
| API8 | Security Misconfiguration | Verbose error / stack trace detection |
| API8 | Injection | SQL/error response pattern matching |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI + Python 3.11+ |
| HTTP Client | httpx (async) |
| AI Orchestration | Direct OpenAI API (GPT-4o) |
| Spec Parsing | PyYAML + custom parser |
| Schema Validation | jsonschema |
| Reporting | Jinja2 (HTML) + JSON |
| Testing | pytest |
| Logging | Rich console + file |
| Frontend | Vanilla JS + CSS (zero deps) |

---

## Research Contributions

To extend this into an academic project:

1. **Comparative study** — Manual vs AI-agent testing time and coverage
2. **Benchmark vulnerable APIs** — OWASP crAPI, DVGA, Juice Shop
3. **False positive analysis** — Measure precision/recall of security findings
4. **LLM model comparison** — GPT-4o vs Claude vs open-source models
5. **CI/CD integration** — GitHub Actions workflow for automated API regression testing

---

## CI/CD Integration (GitHub Actions)

```yaml
# .github/workflows/api-test.yml
name: AI API Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install -r requirements.txt
      - run: python run.py --spec samples/petstore.yaml
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

---

## License

MIT — built for academic and educational use.
