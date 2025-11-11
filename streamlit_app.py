import streamlit as st
from snowflake.snowpark import Session
import base64
from pathlib import Path

# ---------------------------------------------------------
# CONFIGURAÇÃO DO STREAMLIT
# ---------------------------------------------------------
st.set_page_config(page_title="Chat AI - Snowflake Cortex", page_icon="❄️", layout="wide")
st.title("🤖 Chat com Agentes de IA - Snowflake Cortex")

# ---------------------------------------------------------
# PARÂMETROS DE CONEXÃO
# ---------------------------------------------------------
CONN_PARAMS = {
    "account": "A6108453355571-ALMEIDAJR",
    "host": "A6108453355571-ALMEIDAJR.snowflakecomputing.com",
    "user": "TEAMS_INTEGRATION",
    "role": "SYSADMIN",
    "warehouse": "AJ_AGENTE_IA_WH_XS",
    "database": "AJ_DATALAKEHOUSE_VS",
    "schema": "SILVER",
    "private_key_path": "rsa_key.p8"
}

# ---------------------------------------------------------
# FUNÇÃO PARA LER A CHAVE RSA
# ---------------------------------------------------------
def get_private_key():
    key_path = Path(CONN_PARAMS["private_key_path"])
    if not key_path.exists():
        st.error(f"Arquivo de chave não encontrado: {key_path}")
        st.stop()
    with open(key_path, "r") as f:
        key = f.read()
    return key

# ---------------------------------------------------------
# FUNÇÃO DE CONEXÃO COM SNOWFLAKE
# ---------------------------------------------------------
@st.cache_resource
def get_session():
    private_key = get_private_key()
    session = Session.builder.configs({
        "account": CONN_PARAMS["account"],
        "user": CONN_PARAMS["user"],
        "role": CONN_PARAMS["role"],
        "warehouse": CONN_PARAMS["warehouse"],
        "database": CONN_PARAMS["database"],
        "schema": CONN_PARAMS["schema"],
        "private_key": private_key,
    }).create()
    return session

session = get_session()

# ---------------------------------------------------------
# AGENTES DISPONÍVEIS
# ---------------------------------------------------------
agents = {
    "📑 Jurídico (Contratos)": "AJ_JURIDICO_CONTRATOS",
    "🏬 Vendas e Shoppings (VS)": "AJ_SEMANTIC_VIEW_VS",
    "🧾 Protheus (Compras e Contratos)": "AJ_SEMANTIC_PROTHEUS",
    "⚙️ Supply Chain": "AJ_SUPPLY_CHAIN",
}

# ---------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------
st.sidebar.header("⚙️ Configurações")
selected_agent = st.sidebar.selectbox("Selecione o agente de IA:", list(agents.keys()))
agent_name = agents[selected_agent]

st.sidebar.markdown("---")
st.sidebar.markdown("**Warehouse:** AJ_AGENTE_IA_WH_XS")
st.sidebar.markdown("**Role:** SYSADMIN")
st.sidebar.markdown("**Usuário:** TEAMS_INTEGRATION")

# ---------------------------------------------------------
# HISTÓRICO DE CONVERSA
# ---------------------------------------------------------
if "messages" not in st.session_state:
    st.session_state.messages = []

for msg in st.session_state.messages:
    st.chat_message(msg["role"]).write(msg["content"])

# ---------------------------------------------------------
# PROMPT DE ENTRADA
# ---------------------------------------------------------
prompt = st.chat_input("Digite sua pergunta...")

if prompt:
    st.session_state.messages.append({"role": "user", "content": prompt})
    st.chat_message("user").write(prompt)

    with st.spinner(f"Consultando agente {agent_name}..."):
        query = f"""
        SELECT SNOWFLAKE.CORTEX.COMPLETE(
            '{agent_name}',
            '{prompt}'
        ) AS RESPOSTA;
        """
        try:
            result = session.sql(query).collect()
            resposta = result[0]["RESPOSTA"] if result else "Sem resposta retornada."
        except Exception as e:
            resposta = f"⚠️ Erro ao consultar o agente: {e}"

    st.chat_message("assistant").write(resposta)
    st.session_state.messages.append({"role": "assistant", "content": resposta})
