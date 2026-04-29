# CyberSOC Dashboard

Executive and operational dashboard for analyzing cybersecurity attacks in a SOC environment. The project combines a FastAPI backend, a React frontend with interactive visualizations, and an analytical documentation layer built with Jupyter Notebooks.

The goal is to transform `cybersecurity_attacks.csv` into actionable indicators: event volume, severity, blocking effectiveness, attack types, network behavior, anomalies, Firewall/IDS telemetry, geo-intelligence, and filterable logs.

Data source: https://www.kaggle.com/datasets/teamincribo/cyber-security-attacks/data

## Project Stack

| Layer | Technologies | Role in the project |
| --- | --- | --- |
| Backend | Python 3.12, FastAPI, Uvicorn, Pandas, Pydantic | Loads the CSV, normalizes columns, applies global filters, and exposes aggregated data for the dashboard. |
| Frontend | React 18, TypeScript, Vite, TailwindCSS, Recharts, Lucide React | SOC interface with tabs, KPIs, charts, tables, filters, and geographic visualization. |
| Analysis | Jupyter, Pandas, Plotly, nbformat, ipykernel | Reproducible notebooks used to explain analyses and document insights. |
| Data | `cybersecurity_attacks.csv` | Main dataset with security events, network traffic, attacks, severity, logs, and alerts. |

## Structure

```text
.
|-- main.py                         # API entrypoint and compiled frontend server
|-- cybersecurity_attacks.csv        # Dataset used by the dashboard and notebooks
|-- requirements.txt                 # Python/API/notebook dependencies
|-- generate_notebooks.py            # Script that generates the documentation notebooks
|-- backend/
|   `-- app/
|       |-- services/data_loader.py  # CSV loading, normalization, and enrichment
|       `-- services/analytics.py    # Aggregations, KPIs, and filters
|-- frontend/
|   |-- package.json                 # React/Vite dependencies
|   `-- src/                         # Pages, components, and API client
`-- Documentation/
    |-- 01_Overview.ipynb
    |-- 02_Network_Analytics.ipynb
    |-- 03_Threat_Intelligence.ipynb
    |-- 04_Anomaly_Detection.ipynb
    |-- 05_Firewall_IDS.ipynb
    `-- 06_GeoIntelligence.ipynb
```

## Available Analyses

### Overview

Consolidates the SOC executive view: total events, high-priority attacks, blocked attacks, block rate, average anomaly score, unique source IPs, most attacked segment, and dominant protocol.

It also includes an event time series, severity distribution, actions taken, and top offending IPs.

### Threat Intelligence

Maps attack types and their criticality. The analysis crosses `Attack Type` with `Severity Level`, helping identify which vectors concentrate higher-severity events and should receive priority in detection rules.

### Network Analytics

Explores protocols, ports, network segments, and the relationship between `Packet Length` and `Anomaly Scores`. This view helps identify suspicious traffic patterns, event clusters, and possible signs of exfiltration or volumetric attacks.

### Anomaly Detection

Analyzes the statistical distribution of anomaly scores. The dashboard uses a configurable threshold, defaulting to `70`, to separate above-threshold events and highlight the most suspicious records for investigation.

### Firewall & IDS

Validates the effectiveness of perimeter controls. This view crosses severity, action taken, firewall logs, and IDS/IPS alerts to reveal response gaps, events that were only logged, and attacks that should have been blocked.

### Geo Intelligence

Groups events by location to support geo-blocking decisions, regional prioritization, and risk analysis by origin. In the dashboard, the backend normalizes locations into geographic points used by the interactive visualization.

### Logs and Analytics

The logs tab provides an operational view of events with pagination and filters. The Analytics tab combines risk metrics, control effectiveness, network exposure, and event trends into an executive view.

## Jupyter Notebook Documentation

The notebooks in `Documentation/` document the analyses in a reproducible way. They load `cybersecurity_attacks.csv`, apply basic preprocessing with Pandas, and generate Plotly charts using a dark theme aligned with the CyberSOC visual identity.

| Notebook | What it documents | Main charts | Recorded insight |
| --- | --- | --- | --- |
| `01_Overview.ipynb` | Global KPIs, severity, and actions taken | Severity pie chart and `Action Taken` bars | The proportion of high-severity events guides triage; a large Low/Medium volume suggests automation for initial filtering. |
| `02_Network_Analytics.ipynb` | Network traffic, protocols, and packet behavior | Protocol distribution and `Packet Length` vs `Anomaly Scores` scatter plot | Large packets with high scores may indicate exfiltration or volumetric attacks. |
| `03_Threat_Intelligence.ipynb` | Attack types and criticality | Top attack types and attack vs severity heatmap | Vectors that concentrate high severity should become detection priorities. |
| `04_Anomaly_Detection.ipynb` | Anomaly score distribution | Histogram with marginal boxplot | The threshold should be placed where expected traffic separates from the anomaly tail. |
| `05_Firewall_IDS.ipynb` | Firewall/IDS effectiveness | Grouped bars by attack type and action taken | High events that are only logged or ignored indicate the need to review ACLs/rules. |
| `06_GeoIntelligence.ipynb` | Geographic origin of events | Top offensive locations | Recurring origins may justify preventive geo-blocking policies. |

To recreate the notebooks from the script after installing the Python dependencies:

```bash
venv/bin/python generate_notebooks.py
```

To open the interactive documentation:

```bash
venv/bin/jupyter lab Documentation
```

## Data Summary and Generated Insights

The current dataset has `40,000` records and `25` columns, with events between `2020-01-01 00:43:27` and `2023-10-11 19:34:23`.

Main readings from the raw CSV used by the notebooks:

- Balanced severity distribution: `Medium` appears in `13,435` events, `High` in `13,382`, and `Low` in `13,183`.
- Attack types are also evenly distributed: `DDoS` has `13,428` events, `Malware` has `13,307`, and `Intrusion` has `13,265`.
- Protocols: `ICMP` leads with `13,429` events, followed by `UDP` with `13,299` and `TCP` with `13,272`.
- Actions taken in the raw CSV: `Blocked` in `13,529` events, `Ignored` in `13,276`, and `Logged` in `13,195`, producing a raw block rate of `33.82%`.
- Average anomaly score: `50.11`; median: `50.34`; maximum: `100`. There are `12,040` events above the `70` threshold.
- Among `High` events, `4,530` were blocked, `4,392` were only logged, and `4,460` were ignored. This is the main operational concern.
- The dataset has `19,950` records with IDS/IPS alerts and `20,039` with firewall logs, providing material to validate detection and response coverage.

Core insight: the dataset was built with balanced distributions, so its analytical value is less about finding a single dominant category and more about cross-analysis: severity vs action taken, anomaly score vs packet length, attack type vs severity, and geographic origin vs blocking effectiveness.

Note: the notebooks read the raw CSV. The dashboard backend normalizes column names, converts data types, applies filters, and enriches the geographic layer; therefore, some dashboard indicators may differ from the raw notebook numbers.

## Running the Project

### Backend and Dashboard in a Single Server

Install the Python dependencies:

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

Run the application:

```bash
venv/bin/python main.py
```

Then open:

```text
http://127.0.0.1:8000
```

`main.py` starts the FastAPI API and serves the already compiled frontend from `frontend/dist`.

To use another host or port:

```bash
CYBER_HOST=0.0.0.0 CYBER_PORT=8000 venv/bin/python main.py
```

To use another CSV:

```bash
CYBER_CSV_PATH=/path/to/cybersecurity_attacks.csv venv/bin/python main.py
```

### Frontend in Development Mode

```bash
cd frontend
npm install
npm run dev
```

By default, the frontend uses `http://127.0.0.1:8000` as the API. To point it to another URL:

```bash
VITE_API_URL=http://127.0.0.1:8000 npm run dev
```

Production build:

```bash
npm run build
```

## Main Endpoints

```text
GET /health
GET /overview
GET /threats
GET /network
GET /anomalies
GET /firewall-ids
GET /logs
GET /filters
```

Filters accepted by most routes:

```text
start_date
end_date
severity
attack_type
protocol
action_taken
network_segment
min_anomaly_score
search
```

In `/anomalies`, you can also provide:

```text
threshold
```
