# RiskPulse AI
**AI-Driven Cyber Risk Scoring Engine for SMEs**  
Turns raw logs into a single 0–100 threat score + real-time attack-path visualization.

Not a SIEM. A lightweight risk intelligence layer on top of any log source.

### System Architecture (purposed)
# RiskPulse AI – System Architecture

```mermaid
flowchart TD
    subgraph A ["Log Sources (SME Environment)"]
        A1[Windows Workstations\Winlogbeat]
        A2[Linux_Ubuntu_Servers\Filebeat]
        A3[Wazuh_OSSEC_Agents]
        A4[CloudTrail_SaaS_Logs]
    end

    subgraph B ["Ingestion"]
        B1[Beats → JSON over network]
    end

    subgraph C ["Docker Host ($5 VPS or Laptop)"]
        D[("OpenSearch Single Node")]
        E[RiskPulse AI Engine]
    end

    subgraph E
        E1[ML Classifier: TabNet + LightGBM\n→ normal/suspicious/malicious]
        E2[Dynamic Threat Scoring\n0–100 Gauge]
        E3[Probabilistic FSM: Recon → Lateral → Exfil]
        E4[SHAP Explainer: Why this score ?']
    end

    subgraph F ["Frontend"]
        G[Streamlit Dashboard]
        G1[Threat Score Gauge]
        G2[Live Sankey Attack Path]
        G3[Top Risky Assets]
        G4[SHAP Force Plots]
    end

    A --> B1
    B1 --> D
    D <--> E1 & E2 & E3 & E4
    E1 & E2 & E3 --> G

    style C fill:#f0f8ff,stroke:#333,stroke-width:2px
    style G fill:#ffe6e6,stroke:#e60000,stroke-width:4px,rx:15,ry:15
    style E fill:#fff8e6,stroke:#cc9900
    style D fill:#e6f7ff,stroke:#0066cc
```
### Core Features (MVP)
- ML classification (TabNet + SHAP) → normal / suspicious / malicious
- Dynamic Threat Score 0–100 (explainable, auto-weighted)
- Probabilistic FSM attack-path modeling (Recon → Exfil)
- Live Sankey attack flow diagram
- Streamlit dashboard (gauge + Sankey + top risky assets)
- Runs on $5–10/month VPS or Raspberry Pi

### Built For
Small and medium businesses (5–250 employees) that cannot afford or manage Wazuh/Kibana.

### Tech Stack
- Log ingestion: Filebeat / Winlogbeat
- Storage: OpenSearch (single-node)
- ML: TabNet or LightGBM
- Scoring & FSM: Python + NetworkX
- Dashboard: Streamlit + Plotly

### Quick Start
```bash
git clone https://github.com/yourusername/riskpulse-ai.git
cd riskpulse-ai
docker compose up -d          # OpenSearch
pip install -r requirements.txt
python scripts/ingest_sample.py
streamlit run app/main.py
