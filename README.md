# RiskPulse AI
**AI-Driven Cyber Risk Scoring Engine**  
Turns raw logs into a single 0–100 threat score + real-time attack-path visualization.
Anomaly Detection using isolation forest [AP29 dataset] (https://github.com/OTRF/detection-hackathon-apt29/tree/master/datasets/day1) dataset


### Core Features (MVP)
- ML classification (TabNet + SHAP) → normal / suspicious / malicious
- Dynamic Threat Score 0–100 (explainable, auto-weighted)
- Anomaly detection
- ....more will be updated
- Streamlit dashboard (gauge + Sankey + top risky assets)
- Runs on $5–10/month VPS or Raspberry Pi


### Tech Stack
- Storage: OpenSearch (single-node)
- ML: TabNet or LightGBM
- Scoring & FSM: Python
- Dashboard: Streamlit + Plotly

### Quick Start
```bash
git clone https://github.com/yourusername/riskpulse-ai.git
cd riskpulse-ai
docker compose up -d          # OpenSearch
pip install -r requirements.txt
python scripts/ingest_sample.py
streamlit run app/main.py
