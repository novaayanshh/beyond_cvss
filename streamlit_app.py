"""Interactive results dashboard for the Beyond CVSS presentation."""
from pathlib import Path
import pandas as pd
import streamlit as st

ROOT=Path(__file__).resolve().parent
TABLES=ROOT/'outputs'/'tables'

@st.cache_data
def load(name):
    path=TABLES/name
    return pd.read_csv(path) if path.exists() else pd.DataFrame()

st.set_page_config(page_title='Beyond CVSS',page_icon='🛡️',layout='wide')
st.title('Beyond CVSS')
st.subheader('Does EPSS improve vulnerability patch prioritization?')
st.caption('Historical decision-date backtest · CVSS-only vs EPSS-only vs Combined')
panel=load('panel_summary.csv'); rank=load('ranking_results.csv')
coverage=load('historical_cvss_coverage.csv'); models=load('model_results.csv'); tests=load('test_results.csv')
if panel.empty or rank.empty:
    st.error('Project result tables are missing. Run scripts/03_analyze.py first.')
    st.stop()
panel['decision_date']=pd.to_datetime(panel.decision_date)
dates=panel.decision_date.dt.strftime('%Y-%m-%d').tolist()
with st.sidebar:
    st.header('Explore results')
    chosen=st.multiselect('Decision dates',dates,default=dates)
    ks=sorted(rank.k.dropna().astype(int).unique())
    k=st.select_slider('Review budget K',options=ks,value=min(1000,max(ks)))
    cohort=st.radio('Ranking cohort',['common_v3_epss','available'],format_func=lambda x:'Common CVSS 3.x + EPSS' if x=='common_v3_epss' else 'Available per method')
p=panel[panel.decision_date.dt.strftime('%Y-%m-%d').isin(chosen)]
rows=int(p.rows.sum()); positives=int(p.positives.sum()); epss_pct=(1-p.missing_epss.mean())*100 if len(p) else 0
a,b,c,d=st.columns(4)
a.metric('CVE-date rows',f'{rows:,}'); b.metric('Future KEV additions',f'{positives:,}')
c.metric('Positive rate',f'{positives/rows:.3%}' if rows else '—'); d.metric('EPSS availability',f'{epss_pct:.1f}%')
st.markdown('### Ranking performance')
r1,r2=st.columns([1.1,1])
with r1:
    period=rank[rank.cohort.eq(cohort)&rank.k.eq(k)&rank.decision_date.isin(chosen)].copy()
    if not period.empty:
        period['decision_date']=pd.to_datetime(period.decision_date)
        st.markdown('**Recall@K by date**')
        st.line_chart(period.pivot(index='decision_date',columns='method',values='recall_at_k'))
        st.markdown('**Precision@K by date**')
        st.line_chart(period.pivot(index='decision_date',columns='method',values='precision_at_k'))
    else: st.info('No ranking results match these filters.')
with r2:
    st.markdown(f'**Pooled results at K = {k:,}**')
    pooled=rank[rank.decision_date.eq('POOLED')&rank.cohort.eq(cohort)&rank.k.eq(k)]
    if not pooled.empty:
        cols=['method','pool_size','positives_in_pool','recall_at_k','recall_ci_low','recall_ci_high','precision_at_k']
        st.dataframe(pooled[cols].set_index('method').style.format({'pool_size':'{:,.0f}','positives_in_pool':'{:,.0f}','recall_at_k':'{:.3f}','recall_ci_low':'{:.3f}','recall_ci_high':'{:.3f}','precision_at_k':'{:.4%}'}),use_container_width=True)
st.markdown('### Historical CVSS 3.x coverage')
if not coverage.empty:
    cov=coverage[coverage.decision_date.astype(str).isin(chosen)].copy()
    cov['coverage_percent']=100*cov.historical_cvss_3x_rate
    st.bar_chart(cov.set_index('decision_date')['coverage_percent'].rename('Coverage (%)'))
st.markdown('### Machine learning holdout')
if not models.empty:
    mt=models[models.split.eq('test')].copy()
    if not mt.empty:
        st.caption(f"Precomputed final holdout: {mt.decision_date.iloc[0]}. Opening this dashboard does not retrain models.")
        st.dataframe(mt[['model','feature_set','rows','positives','average_precision','recall_at_1000']].sort_values(['model','feature_set']).style.format({'rows':'{:,.0f}','positives':'{:,.0f}','average_precision':'{:.6f}','recall_at_1000':'{:.3f}'}),use_container_width=True,hide_index=True)
        st.bar_chart(mt.pivot(index='model',columns='feature_set',values='average_precision'))
st.markdown('### Hypothesis tests')
if not tests.empty:
    cols=['hypothesis','decision_date','test','effect','p_value','p_holm_within_hypothesis','positives']
    st.dataframe(tests[cols].rename(columns={'p_value':'p-value','p_holm_within_hypothesis':'Holm-adjusted p','positives':'Positive rows'}),use_container_width=True,hide_index=True)
st.info('Retrospective catalogue-addition study, not causal evidence or an automatic patch recommendation. Outcomes are rare, CVEs repeat across snapshots, and the final ML test date has only 19 positives.')
st.caption('Sources: NVD · FIRST EPSS · CISA KEV');
