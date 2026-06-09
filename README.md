# AI-Based Intelligent Vulnerability Scoring System

![Status](https://img.shields.io/badge/status-active-success?style=flat)
![Version](https://img.shields.io/badge/version-v1.0-blue?style=flat)
![Python](https://img.shields.io/badge/python-3.x-3776AB?style=flat\&logo=python\&logoColor=white)
![Docker](https://img.shields.io/badge/docker-enabled-2496ED?style=flat\&logo=docker\&logoColor=white)
![Playwright](https://img.shields.io/badge/playwright-automation-2EAD33?style=flat\&logo=playwright\&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/postgresql-supported-4169E1?style=flat\&logo=postgresql\&logoColor=white)
![CVSS](https://img.shields.io/badge/CVSS-v3.1-orange?style=flat)
![EBSS](https://img.shields.io/badge/EBSS-behavior--based-success?style=flat)
![AI](https://img.shields.io/badge/AI-LLM%20Powered-purple?style=flat)

---

## Overview

AI-Based Intelligent Vulnerability Scoring System (AI-VSS) is an autonomous cybersecurity testing platform that combines AI-assisted attack generation, runtime observability, and intelligent vulnerability scoring.

The system automatically clones GitHub repositories, detects technology stacks, deploys isolated Docker environments, executes intelligent attack simulations, monitors application behavior, and generates professional security reports with CVSS v3.1 and Extended Behavior-Based Security Score (EBSS).

---
<img width="1107" height="543" alt="Screenshot 2026-06-09 at 1 00 19 PM" src="https://github.com/user-attachments/assets/3fb4ebab-7f5b-4332-8ae0-f3a043d5c6d2" />

## Key Features

* Automated GitHub repository analysis
* Technology stack fingerprinting
* Dynamic Docker environment generation
* AI-assisted attack orchestration
* Playwright-based application crawling
* Runtime observability and monitoring
* CVSS v3.1 severity scoring
* Extended Behavior-Based Security Score (EBSS)
* Professional HTML security reports
* Safe containerized attack execution

---

## Architecture

```text
User Repository URL
        │
        ▼
Repository Cloner
        │
        ▼
Stack Detection Engine
        │
        ▼
Docker Environment Generator
        │
        ▼
Target Application Deployment
        │
        ▼
AI Attack Orchestrator
        │
        ▼
Observability & Monitoring
        │
        ▼
CVSS + EBSS Calculation
        │
        ▼
Security Report Generator
```

## Technology Stack

### Core Technologies

* Python
* Docker
* Docker Compose
* Playwright
* PostgreSQL
* Git

### AI Components

* Large Language Models (LLMs)
* AI-based Payload Generation
* Adaptive Attack Suggestions
* Security Classification Engine

### Monitoring Components

* Runtime Telemetry Collection
* Container Statistics Monitoring
* Database Performance Monitoring
* Log Correlation System

---

## Workflow

1. User submits GitHub repository URL.
2. Repository is cloned locally.
3. Technology stack is detected.
4. Docker Compose configuration is generated.
5. Application is deployed inside isolated containers.
6. Playwright crawler maps application endpoints.
7. AI engine generates attack payloads.
8. Attacks execute inside sandboxed attacker containers.
9. Runtime metrics are continuously monitored.
10. CVSS and EBSS scores are calculated.
11. Professional HTML report is generated.

---

## Supported Security Tests

### Web Security

* SQL Injection
* Cross-Site Scripting (XSS)
* Authentication Bypass Testing
* API Abuse Detection
* Command Injection Testing

### Behavioral Analysis

* CPU Utilization Monitoring
* Memory Consumption Analysis
* Response Latency Tracking
* Error Log Analysis
* Database Performance Monitoring

---

## Security Scoring

### CVSS v3.1

Industry-standard vulnerability severity scoring based on:

* Attack Vector
* Attack Complexity
* Privileges Required
* User Interaction
* Confidentiality Impact
* Integrity Impact
* Availability Impact

### Extended Behavior-Based Security Score (EBSS)

Custom scoring model based on runtime impact:

| Behavior Metric              | Weight |
| ---------------------------- | ------ |
| CPU Spike                    | +4     |
| DB Error Rate Spike          | +3     |
| Sensitive Data Exposure      | +5     |
| Successful Data Exfiltration | +8     |
| Container Crash              | +6     |
| Response Time > 3x Baseline  | +2     |

---

## Example Output

The generated report includes:

* Attack Timeline
* Vulnerability Findings
* CVSS Scores
* EBSS Scores
* Runtime Metrics
* Observability Graphs
* Impact Analysis
* CWE References
* Remediation Recommendations

---

## Hardware Requirements

| Component | Requirement         |
| --------- | ------------------- |
| Processor | Intel i5 / Ryzen 5+ |
| RAM       | 8 GB Minimum        |
| Storage   | 20 GB Free Space    |
| Internet  | Required            |
| OS        | Windows / Linux     |

---

## Software Requirements

| Software       | Version |
| -------------- | ------- |
| Python         | 3.x     |
| Docker         | Latest  |
| Docker Compose | Latest  |
| Playwright     | Latest  |
| Git            | Latest  |

---

## Future Scope

* Autonomous exploit chaining
* Machine learning vulnerability prediction
* Kubernetes security testing
* Cloud-native deployment analysis
* DevSecOps integration
* GitHub Actions support
* Real-time monitoring dashboards
* Framework-specific exploit modules
* Offline enterprise security mode

---

## Project Team

### Developers

* Niraj Naphade
* Atharva Padwal
* Shruti Mogre

### Guide

* Prof. Nikhil Sardar

### Co-Guide

* Mr. Uday Mithapelli

---

## License

This project is developed for academic and research purposes.

---

## Disclaimer

This platform is intended solely for authorized security testing, cybersecurity education, and research. Users must obtain proper permission before testing any target system.
<img width="1132" height="546" alt="Screenshot 2026-06-09 at 12 59 53 PM" src="https://github.com/user-attachments/assets/7237a14d-62b5-4321-b232-0958e3d891c5" />
