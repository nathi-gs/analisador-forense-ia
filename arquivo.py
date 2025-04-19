import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta

st.set_page_config(page_title="Análise Forense", layout="wide")

# Estilo customizado
modo_escuro = st.sidebar.checkbox("Modo escuro", value=True)

if modo_escuro:
    st.markdown("""
        <style>
        .main { background-color: #0e1117; color: #f1f1f1; }
        header, footer { visibility: hidden; }
        .block-container { padding-top: 2rem; padding-bottom: 2rem; }
        h1, h2, h3, h4 { color: #00cc44; }
        </style>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
        <style>
        .main { background-color: #ffffff; color: #000000; }
        header, footer { visibility: hidden; }
        .block-container { padding-top: 2rem; padding-bottom: 2rem; }
        h1, h2, h3, h4 { color: #00cc44; }
        </style>
    """, unsafe_allow_html=True)

# Menu lateral de navegação
st.sidebar.title("Menu de Navegação")
selecao = st.sidebar.radio("Ir para:", ["Resumo", "Gráficos", "Análise por Usuário/IP", "Relatório", "Todos os Logs"])

# Carregar os dados
@st.cache_data
def carregar_dados():
    df = pd.read_csv("logs_forenses_simulados.csv")
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

df = carregar_dados()
df['timestamp_formatado'] = df['timestamp'].dt.strftime('%d/%m/%y %H:%M:%S')

# Filtro por intervalo de datas
st.sidebar.subheader("Filtrar por Data")
data_inicio = st.sidebar.date_input("Data inicial", df['timestamp'].min().date())
data_fim = st.sidebar.date_input("Data final", df['timestamp'].max().date())

df = df[(df['timestamp'].dt.date >= data_inicio) & (df['timestamp'].dt.date <= data_fim)]

# Identificar eventos suspeitos
suspeitos = []
falhas_login = df[df['action'] == 'login_failed'].sort_values('timestamp')
for user in falhas_login['user'].unique():
    user_logs = falhas_login[falhas_login['user'] == user]
    for i in range(len(user_logs) - 3):
        janela = user_logs.iloc[i:i+4]
        if (janela.iloc[-1]['timestamp'] - janela.iloc[0]['timestamp']) <= timedelta(minutes=10):
            suspeitos.append(janela)

suspeitos.append(df[(df['action'] == 'privilege_escalation') & (df['user'] != 'admin')])
suspeitos.append(df[(df['action'] == 'usb_connected') & (df['timestamp'].dt.hour < 6)])
suspeitos.append(df[df['user'] == 'hacker'])
suspeitos.append(df[df['severity'].isin(['high', 'critical'])])

df_suspeitos = pd.concat(suspeitos).drop_duplicates().sort_values('timestamp')
df_suspeitos['timestamp_formatado'] = df_suspeitos['timestamp'].dt.strftime('%d/%m/%y %H:%M:%S')

# Conteúdo dinâmico baseado na seleção do menu
if selecao == "Resumo":
    st.markdown("""
        <h1 style='text-align: center;'>Analisador Forense</h1>
        <p style='text-align: center;'>Detecte atividades suspeitas em ambientes corporativos</p>
    """, unsafe_allow_html=True)

    st.subheader("Eventos Suspeitos Detectados")
    st.dataframe(df_suspeitos[['timestamp_formatado', 'user', 'action', 'device', 'severity']])

    st.success(f"Total de eventos suspeitos: {len(df_suspeitos)}")
    if len(df_suspeitos) > 10:
        st.error("ALERTA: Grande volume de eventos suspeitos detectado!")

elif selecao == "Gráficos":
    st.subheader("Visualizações Gráficas")
    col1, col2 = st.columns(2)
    with col1:
        fig1 = px.histogram(df, x="action", color="severity", title="Distribuição de Ações por Severidade",
                            labels={"action": "Ação", "severity": "Severidade"})
        st.plotly_chart(fig1, use_container_width=True)

    with col2:
        fig2 = px.pie(df, names="severity", title="Proporção de Severidade dos Eventos",
                      labels={"severity": "Severidade"})
        st.plotly_chart(fig2, use_container_width=True)

    fig3 = px.line(df.sort_values('timestamp'), x="timestamp", title="Linha do Tempo dos Eventos", markers=True,
                   labels={"timestamp": "Data/Hora"})
    st.plotly_chart(fig3, use_container_width=True)

elif selecao == "Análise por Usuário/IP":
    st.subheader("Análise por Usuário / IP")
    usuarios = df['user'].unique()
    ips = df['device'].unique()

    usuario_selecionado = st.selectbox("Selecione um usuário", usuarios)
    ip_selecionado = st.selectbox("Selecione um IP/dispositivo", ips)

    st.markdown(f"### Eventos do usuário {usuario_selecionado}")
    df_usuario = df[df['user'] == usuario_selecionado].sort_values('timestamp')
    df_usuario['timestamp_formatado'] = df_usuario['timestamp'].dt.strftime('%d/%m/%y %H:%M:%S')
    st.dataframe(df_usuario[['timestamp_formatado', 'action', 'device', 'severity']])

    st.markdown("**Resumo de comportamento do usuário:**")
    st.write(f"Total de eventos: {len(df_usuario)}")
    st.write(f"Ações únicas realizadas: {df_usuario['action'].nunique()}")
    st.write(f"Eventos suspeitos deste usuário: {len(df_suspeitos[df_suspeitos['user'] == usuario_selecionado])}")

    st.markdown(f"### Eventos no dispositivo {ip_selecionado}")
    df_ip = df[df['device'] == ip_selecionado].sort_values('timestamp')
    df_ip['timestamp_formatado'] = df_ip['timestamp'].dt.strftime('%d/%m/%y %H:%M:%S')
    st.dataframe(df_ip[['timestamp_formatado', 'user', 'action', 'severity']])

elif selecao == "Relatório":
    st.subheader("Relatório de Eventos Suspeitos")
    csv = df_suspeitos.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="Baixar relatório CSV",
        data=csv,
        file_name='eventos_suspeitos.csv',
        mime='text/csv',
    )

elif selecao == "Todos os Logs":
    st.subheader("Todos os eventos registrados")
    df['timestamp_formatado'] = df['timestamp'].dt.strftime('%d/%m/%y %H:%M:%S')
    st.dataframe(df[['timestamp_formatado', 'user', 'action', 'device', 'severity']])