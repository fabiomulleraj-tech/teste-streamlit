import streamlit as st
import base64
from snowflake.snowpark import Session
from cryptography.hazmat.primitives import serialization

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
    "user": "TEAMS_INTEGRATION",
    "role": "SYSADMIN",
    "warehouse": "AJ_AGENTE_IA_WH_XS",
    "database": "AJ_DATALAKEHOUSE_VS",
    "schema": "SILVER",
}

# ---------------------------------------------------------
# LER CHAVE PRIVADA DO st.secrets
# ---------------------------------------------------------
def get_private_key():
    try:
        pem_key = st.secrets["rsa"]["private_key"].encode()
        p_key = serialization.load_pem_private_key(pem_key, password=None)
        private_key = p_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return base64.b64encode(private_key).decode("utf-8")
    except Exception as e:
        st.error(f"Erro ao ler a chave privada: {e}")
        st.stop()

# ---------------------------------------------------------
# CRIAR SESSÃO SNOWFLAKE
# ---------------------------------------------------------
@st.cache_resource
def get_session():
    try:
        private_key = get_private_key()
        session = Session.builder.configs({
            "account": CONN_PARAMS["account"],
            "user": CONN_PARAMS["user"],
            "role": CONN_PARAMS["role"],
            "warehouse": CONN_PARAMS["warehouse"],
            "database": CONN_PARAMS["database"],
            "schema": CONN_PARAMS["schema"],
            "private_key": private_key,
            "authenticator": "SNOWFLAKE_JWT",
        }).create()
        return session
    except Exception as e:
        st.error(f"❌ Falha ao conectar ao Snowflake: {e}")
        st.stop()

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
st.sidebar.write(f"**Warehouse:** {CONN_PARAMS['warehouse']}")
st.sidebar.write(f"**Role:** {CONN_PARAMS['role']}")
st.sidebar.write(f"**Usuário:** {CONN_PARAMS['user']}")

# ---------------------------------------------------------
# HISTÓRICO DE CONVERSA
# ---------------------------------------------------------
if "messages" not in st.session_state:
    st.session_state.messages = []

for msg in st.session_state.messages:
    st.chat_message(msg["role"]).write(msg["content"])

# ---------------------------------------------------------
# PROMPT DO USUÁRIO
# ---------------------------------------------------------
prompt = st.chat_input("Digite sua pergunta...")

if prompt:
    st.session_state.messages.append({"role": "user", "content": prompt})
    st.chat_message("user").write(prompt)

    with st.spinner(f"Consultando agente {agent_name}..."):
        try:
            query = f"""
                SELECT SNOWFLAKE.CORTEX.COMPLETE(
                    '{agent_name}',
                    '{prompt}'
                ) AS RESPOSTA;
            """
            result = session.sql(query).collect()
            resposta = result[0]["RESPOSTA"] if result else "⚠️ Nenhuma resposta retornada."
        except Exception as e:
            resposta = f"⚠️ Erro ao consultar o agente: {e}"

    st.chat_message("assistant").write(resposta)
    st.session_state.messages.append({"role": "assistant", "content": resposta})
