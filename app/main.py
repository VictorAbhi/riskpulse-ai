import streamlit as st
from opensearchpy import OpenSearch

st.title("RiskPulse AI Dashboard")
st.metric("Current Threat Score", "42", "+34")

client = OpenSearch(hosts=[{'host': 'localhost', 'port': 9201}], use_ssl=False)
res = client.search(index="riskpulse-logs", size=10)

st.write("Latest events")
st.dataframe([hit["_source"] for hit in res["hits"]["hits"]])