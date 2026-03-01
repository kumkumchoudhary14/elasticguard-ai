# ElasticGuard AI 🛡️

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://python.org)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.12-yellow.svg)](https://elastic.co)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109-009688.svg)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **AI-powered IoT Security Observability Platform** — Built for the Elastic Forge The Future Singapore Hackathon

---

## 🌟 Problem Statement

Modern IoT deployments generate massive volumes of security telemetry — access logs, network flows, temperature anomalies, and camera alerts — that are impossible to monitor manually. Security teams need an intelligent platform that can **ingest, analyze, and surface threats in real-time**, turning raw device logs into actionable security intelligence.

## 💡 Solution

**ElasticGuard AI** is a complete, production-ready security observability platform that:

- 🔌 **Simulates 4 types of IoT devices** (temperature sensors, security cameras, access controllers, network switches) generating realistic security events across Singapore locations
- ⚡ **Streams events into Elasticsearch** using optimized index templates, ILM policies, and bulk ingestion
- 🤖 **Detects anomalies automatically** using Z-score analysis and Isolation Forest ML algorithms
- 🧠 **Generates AI threat summaries** with threat classification, scoring (0–100), and remediation guidance — no external LLM API needed
- 📊 **Serves a real-time dashboard** with live charts, event feeds, and threat alerts
- 🐳 **Runs with one command** via Docker Compose

---

## ��️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   ElasticGuard AI                       │
│                                                         │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────┐  │
│  │IoT Simulator│───▶│ Elasticsearch│◀───│  FastAPI  │  │
│  │iot_simulator│    │   (8.12)     │    │  Backend  │  │
│  │  .py        │    │              │    │  :8000    │  │
│  └─────────────┘    │ iot-security │    └─────┬─────┘  │
│                     │ -events-*    │          │        │
│  ┌─────────────┐    │              │    ┌─────▼─────┐  │
│  │  Anomaly    │───▶│ security-    │    │ Dashboard │  │
│  │  Detector   │    │ anomalies    │    │ index.html│  │
│  │  (ML/AI)    │    └──────────────┘    └───────────┘  │
│  └─────────────┘                                        │
│                     ┌──────────────┐                   │
│  ┌─────────────┐    │    Kibana    │                   │
│  │  Threat     │    │   (8.12)     │                   │
│  │Intelligence │    │   :5601      │                   │
│  └─────────────┘    └──────────────┘                   │
└─────────────────────────────────────────────────────────┘
```

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔌 **IoT Simulation** | 4 device types, 50+ event types, Singapore-themed locations, realistic metrics |
| 📥 **Bulk Ingestion** | Elasticsearch bulk API with optimized index templates and ILM policies |
| 🤖 **ML Anomaly Detection** | Z-score (per metric) + Isolation Forest (multivariate) |
| 🧠 **AI Threat Intelligence** | Rule-based threat classification into 6 categories with 0–100 scoring |
| 🔍 **Powerful Search** | Full-text, filtered, and advanced DSL search via FastAPI |
| 📊 **Analytics API** | Timeline, severity distribution, device stats, top threats |
| 🖥️ **Real-time Dashboard** | Dark-themed SPA with Chart.js, auto-refresh every 5s |
| 🐳 **One-command Deploy** | `docker compose up --build` — zero additional setup |

---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose installed
- 4GB RAM available (for Elasticsearch)

### Start Everything

```bash
# 1. Clone the repository
git clone https://github.com/kumkumchoudhary14/elasticguard-ai.git
cd elasticguard-ai

# 2. Copy environment config
cp .env.example .env

# 3. Start all services
docker compose up --build
```

### Access Services

| Service | URL |
|---------|-----|
| 🖥️ **Dashboard** | http://localhost:8000 |
| 🔌 **API Docs** | http://localhost:8000/docs |
| 📊 **Kibana** | http://localhost:5601 |
| 🔍 **Elasticsearch** | http://localhost:9200 |

### Setup Elasticsearch (optional, recommended)

```bash
# Run index template and ILM setup
python setup_elasticsearch.py

# Start IoT data simulation (separate terminal)
python iot_simulator.py

# Start anomaly detection (separate terminal)
python anomaly_detector.py
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Search & Storage** | Elasticsearch 8.12 |
| **Visualization** | Kibana 8.12 |
| **Backend API** | FastAPI 0.109 + Uvicorn |
| **ML/AI** | scikit-learn (Isolation Forest), NumPy (Z-score) |
| **Dashboard** | Vanilla JS + Chart.js + Tailwind CSS |
| **Container** | Docker + Docker Compose |
| **Language** | Python 3.11 |

---

## 📡 API Reference

### Search Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/search` | Full-text search with filters (severity, device_type, time_range) |
| GET | `/api/search/advanced` | Advanced Elasticsearch DSL query search |
| GET | `/api/events/latest` | Latest N security events |

### Analytics Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/analytics/overview` | Dashboard stats (events, anomalies, devices, alerts) |
| GET | `/api/analytics/timeline` | Event timeline by time bucket |
| GET | `/api/analytics/top-threats` | Top threat categories |
| GET | `/api/analytics/device-stats` | Per-device event and anomaly counts |
| GET | `/api/analytics/severity-distribution` | Events grouped by severity |

### Threat Intelligence Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/threats` | List detected anomalies/threats |
| GET | `/api/threats/{id}` | Threat details with AI-generated summary |
| POST | `/api/threats/analyze` | Trigger anomaly detection on recent data |
| GET | `/api/threats/summary` | AI threat landscape summary |

### Health
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | App + Elasticsearch health status |

---

## 🤖 How Anomaly Detection Works

### 1. Z-Score Detection (Per-Metric)
For each metric (CPU, memory, temperature, network_in, network_out):
```
Z = |X - μ| / σ
```
Events with Z > 3.0 on any metric are flagged as anomalies.

### 2. Isolation Forest (Multivariate)
All 5 metrics are combined into a feature vector, standardized, and fed to `sklearn.IsolationForest`. Points in low-density regions (contamination=10%) are flagged as anomalous.

### 3. Threat Classification
Detected anomalies are classified into 6 categories:
- `brute_force` — repeated authentication failures
- `ddos` — extreme network_in spikes
- `data_exfiltration` — extreme network_out spikes
- `unauthorized_access` — access controller anomalies
- `network_scan` — port scan patterns
- `device_tampering` — temperature/hardware anomalies

### 4. Threat Scoring (0–100)
```
score = base_severity_score + (anomaly_score/100 × 20)
        + repeat_bonus + multi_device_bonus
```

---

## 📁 Project Structure

```
elasticguard-ai/
├── README.md                 # This file
├── LICENSE                   # MIT License
├── docker-compose.yml        # Multi-service orchestration
├── Dockerfile                # Python 3.11-slim app container
├── requirements.txt          # Python dependencies
├── .env.example              # Environment variable template
├── setup_elasticsearch.py    # ES index templates + ILM + pipelines
├── iot_simulator.py          # IoT device event simulator
├── anomaly_detector.py       # Z-score + Isolation Forest ML
├── threat_intelligence.py    # Threat classification + summarization
├── app/
│   ├── main.py               # FastAPI app + CORS + lifespan
│   ├── config.py             # Settings from env vars
│   ├── models.py             # Pydantic models
│   ├── elasticsearch_client.py
│   ├── routes/
│   │   ├── health.py         # GET /api/health
│   │   ├── search.py         # GET /api/search, /api/events/latest
│   │   ├── analytics.py      # GET /api/analytics/*
│   │   └── threats.py        # GET/POST /api/threats/*
│   └── services/
│       ├── search_service.py
│       ├── analytics_service.py
│       └── threat_service.py
├── static/
│   └── index.html            # Real-time dashboard SPA
└── tests/
    ├── test_simulator.py     # IoT simulator unit tests
    ├── test_anomaly_detector.py
    └── test_api.py           # FastAPI endpoint tests
```

---

## 🧪 Running Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

---

## 🌏 Hackathon Context

**Event**: Elastic Forge The Future — Singapore  
**Themes Demonstrated**:
- ✅ **Search** — Full-text, filtered, and advanced DSL search
- ✅ **Observability** — Real-time IoT telemetry dashboards and metrics
- ✅ **Security** — Threat detection, anomaly scoring, and incident response
- ✅ **IoT** — 4 device types simulating real Singapore infrastructure
- ✅ **ML/AI** — Isolation Forest + Z-score anomaly detection + AI threat summaries

---

## 👥 Team

Built with ❤️ for Elastic Forge The Future Singapore Hackathon.

---

## 📄 License

[MIT License](LICENSE) — see LICENSE file for details.
