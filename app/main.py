import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import networkx as nx
from opensearchpy import OpenSearch
from datetime import datetime

# ────────────────────────────────────────────────────────────────
# CONFIGURATION
# ────────────────────────────────────────────────────────────────
OPENSEARCH_HOST = 'localhost'
OPENSEARCH_PORT = 9201
INDEX_NAME = 'riskpulse-logs'          # ← change if your index has different name

# ────────────────────────────────────────────────────────────────
# Connect to OpenSearch
# ────────────────────────────────────────────────────────────────
@st.cache_resource
def get_opensearch_client():
    return OpenSearch(
        hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
        http_auth=None,                # ← add ('admin', 'admin') if you use default dev creds
        use_ssl=False,
        verify_certs=False,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
        timeout=30
    )

client = get_opensearch_client()

# ────────────────────────────────────────────────────────────────
# Load Data
# ────────────────────────────────────────────────────────────────
def load_data():
    query = {
        "query": {"match_all": {}},
        "size": 1500,                   # ← adjust according to your needs
        "sort": [{"@timestamp": {"order": "desc"}}]
    }

    try:
        response = client.search(index=INDEX_NAME, body=query)
        hits = response['hits']['hits']
        if not hits:
            return None
        return [hit['_source'] for hit in hits]
    except Exception as e:
        st.error(f"Failed to connect/query OpenSearch: {str(e)}")
        st.info("Is OpenSearch running? Check docker logs / port / credentials.")
        return None

raw_data = load_data()

if raw_data is None or len(raw_data) == 0:
    st.warning("No data found in index **riskpulse-logs**")
    st.info("Run your ingestion script first or check index name.")
    st.stop()

# ────────────────────────────────────────────────────────────────
# Prepare DataFrame
# ────────────────────────────────────────────────────────────────
df = pd.DataFrame(raw_data)

# Convert timestamp (very useful for future time-based weighting)
if '@timestamp' in df.columns:
    df['@timestamp'] = pd.to_datetime(df['@timestamp'])

# ────────────────────────────────────────────────────────────────
# RULE-BASED CLASSIFICATION (MVP – expand later with ML)
# ────────────────────────────────────────────────────────────────
df['classification'] = 'normal'

# Helper: safe string contains
def safe_contains(series, pattern, case=False):
    return series.str.contains(pattern, case=case, na=False)

# Suspicious patterns for EventID 10 (ProcessAccess)
suspicious_conditions = (
    # PowerShell related call traces (very common in attacks)
    safe_contains(df['CallTrace'], 'psmserviceexthost.dll') |
    
    # Suspicious granted access masks (memory write / full control)
    (df['GrantedAccess'].isin(['0x1F0FFF', '0x1FFFFF', '0x1438'])) |
    
    # SYSTEM → svchost access pattern (common for injection/recon)
    (safe_contains(df['SourceImage'], 'svchost.exe') &
     safe_contains(df['TargetImage'], 'svchost.exe') &
     (df['UserID'] == 'S-1-5-18'))
)

df.loc[suspicious_conditions & (df['EventID'] == 10), 'classification'] = 'suspicious'

# You can add 'malicious' rules later (e.g. write+execute rights + known bad parent/child combos)

# ────────────────────────────────────────────────────────────────
# THREAT SCORE CALCULATION
# ────────────────────────────────────────────────────────────────
counts = df['classification'].value_counts()
n_normal     = counts.get('normal', 0)
n_suspicious = counts.get('suspicious', 0)
n_malicious  = counts.get('malicious', 0)

total_events = len(df)

# Base contribution
score = 0
score += n_suspicious * 15
score += n_malicious  * 45

# Bonus for recent suspicious activity (last 24 hours)
if '@timestamp' in df.columns and not df['@timestamp'].empty:
    try:
        # Ensure consistent timezone handling
        now_utc = pd.Timestamp.now(tz='UTC')
        cutoff = now_utc - pd.Timedelta(hours=24)
        
        recent = df[df['@timestamp'] >= cutoff]
        recent_susp = (recent['classification'] == 'suspicious').sum()
        score += recent_susp * 8  # Extra weight for fresh activity
    except Exception as e:
        st.warning(f"Time-based scoring skipped due to timestamp issue: {e}")
        recent_susp = 0
else:
    recent_susp = 0

# Normalize by volume
volume_factor = min(1.0, (total_events ** 0.7) / 150)
threat_score = min(100, int(score * volume_factor))

# ────────────────────────────────────────────────────────────────
# ATTACK PATH FSM (very basic for MVP)
# ────────────────────────────────────────────────────────────────
G = nx.DiGraph()
states = ['Recon', 'Initial Access', 'Lateral Movement', 'Exfil']
G.add_nodes_from(states)

# Very simple transition probabilities
prob_recon_to_lateral = min(0.8, n_suspicious / max(1, total_events * 0.1))
prob_lateral_to_exfil = 0.35 if n_suspicious >= 3 else 0.0

G.add_edge('Recon', 'Lateral Movement', weight=prob_recon_to_lateral)
G.add_edge('Lateral Movement', 'Exfil', weight=prob_lateral_to_exfil)

# Sankey preparation
source, target, value = [], [], []
for src, dst, d in G.edges(data=True):
    source.append(states.index(src))
    target.append(states.index(dst))
    value.append(round(d['weight'] * 100, 1))  # percentage-like scale

# ────────────────────────────────────────────────────────────────
# STREAMLIT DASHBOARD
# ────────────────────────────────────────────────────────────────
st.title("RiskPulse AI · Threat Dashboard")
st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Events: {total_events:,}")

col1, col2 = st.columns([1, 1.3])

with col1:
    st.subheader("Threat Score")
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=threat_score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Current Risk Level"},
        delta={'reference': 40},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 40],  'color': "#d4edda"},
                {'range': [40, 70], 'color': "#fff3cd"},
                {'range': [70, 100],'color': "#f8d7da"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.8,
                'value': 85
            }
        }
    ))
    fig_gauge.update_layout(height=250, margin=dict(l=20, r=20, t=40, b=20))
    st.plotly_chart(fig_gauge, use_container_width=True)

with col2:
    st.subheader("Attack Path Probability")
    if any(value):
        fig_sankey = go.Figure(go.Sankey(
            node=dict(
                pad=15, thickness=20,
                line=dict(color="black", width=0.5),
                label=states,
                color=["#a6cee3", "#1f78b4", "#b2df8a", "#33a02c"]
            ),
            link=dict(
                source=source,
                target=target,
                value=value,
                color=["rgba(31,120,180,0.4)", "rgba(178,223,138,0.5)"]
            )
        ))
        fig_sankey.update_layout(height=300, margin=dict(l=10, r=10, t=20, b=20))
        st.plotly_chart(fig_sankey, use_container_width=True)
    else:
        st.info("No meaningful attack path detected yet.")

# ────────────────────────────────────────────────────────────────
# Risky Assets
# ────────────────────────────────────────────────────────────────
st.subheader("Top Risky Assets / Targets")
risky = df[df['classification'] != 'normal'].groupby(
    ['Hostname', 'TargetImage', 'classification'],
    as_index=False
).size().rename(columns={'size': 'Event Count'})

if not risky.empty:
    risky = risky.sort_values('Event Count', ascending=False)
    st.dataframe(
        risky.style.highlight_max(subset=['Event Count'], color='#ffcccc'),
        use_container_width=True
    )
else:
    st.success("No suspicious or malicious activity detected.")
