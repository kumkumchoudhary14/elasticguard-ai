# Running ElasticGuard AI in GitHub Codespaces

## Quick Start

1. Click "Create codespace on main" from the repo page
2. Wait for the Codespace to build (~2 minutes)
3. In the terminal, run:
   ```
   docker-compose up --build
   ```
4. Wait for Elasticsearch to be healthy (~30 seconds)
5. Open a new terminal and seed data:
   ```
   python iot_simulator.py
   ```
6. Click the forwarded port 8000 URL to open the dashboard!

## Ports

| Port | Service | Description |
|------|---------|-------------|
| 8000 | FastAPI App | Dashboard & REST API |
| 5601 | Kibana | Elasticsearch visualization |
| 9200 | Elasticsearch | Search engine |

## Tips

- The dashboard auto-refreshes every 5 seconds
- Run `python anomaly_detector.py` to trigger ML-based threat detection
- Use the REST Client VS Code extension to test API endpoints
