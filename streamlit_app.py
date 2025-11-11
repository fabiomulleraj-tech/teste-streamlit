import streamlit as st
import base64
import time
import jwt
import hashlib
from snowflake.snowpark import Session
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------
# CONFIGURAÇÃO DO APP
# ---------------------------------------------------------
st.set_page_config(page_title="Chat AI - Snowflake Cortex", page_icon="❄️", layout="wide")
st.title("🤖 Chat com Agentes de IA - Snowflake Cortex")

ACCOUNT = "A6108453355571-ALMEIDAJR"
USER = "TEAMS_INTEGRATION"
ROLE = "SYSADMIN"
WAREHOUSE = "AJ_AGENTE_IA_WH_XS"
DATABASE = "AJ_DATALAKEHOUSE_VS"
SCHEMA = "SILVER"
RSA_KEY_PATH = "rsa_key.p8"

# ---------------------------------------------------------
# GERADOR DE JWT (baseado na sua versão Node)
# ---------------------------------------------------------
class JWTGenerator:
    def __init__(self, account, user, key_path):
        self.account = self._prepare_account_name(account)
        self.user = user.upper()
        self.qualified_username = f"{self.account}.{self.user}"
        self.lifetime = 3600  # 1 hora
        self.renewal_delay = self.lifetime - 300  # renova 5min antes
        self.private_key_pem = open(key_path, "rb").read()
        self.private_key = serialization.load_pem_private_key(
            self.private_key_pem, password=None, backend=default_backend()
        )
        self.public_fingerprint = self._calculate_public_key_fingerprint()
        self.token = None
        self.renew_time = 0
        self.generate_token()

    def _prepare_account_name(self, raw_account):
        if ".global" in raw_account:
            return raw_account.split("-")[0].upper()
        return raw_account.split(".")[0].upper()

    def _calculate_public_key_fingerprint(self):
        public_key = self.private_key.public_key()
        der_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        sha256_digest = hashlib.sha256(der_public_key).digest()
        fingerprint = f"SHA256:{base64.b64encode(sha256_digest).decode('utf-8')}"
        return fingerprint

    def generate_token(self):
        now = int(time.time())
        payload = {
            "iss": f"{self.qualified_username}.{self.public_fingerprint}",
            "sub": self.qualified_username,
            "iat": now,
            "exp": now + self.lifetime,
        }
        self.token = jwt.encode(payload, self.private_key_pem, algorithm="RS256")
        self.renew_time = now + self.renewal_delay
        return self.token

    def get_token(self):
        now = int(time.time())
        if now >= self.renew_time:
            print("♻️ Regenerando JWT...")
            self.generate_token()
        return self.token


# ---------------------------------------------------------
# CRIAR SESSÃO SNOWFLAKE
# ---------------------------------------------------------
@st.cache_resource
def get_session():
    jwt_gen = JWTGenerator(ACCOUNT, USER, RSA_KEY_PATH)
    token = jwt_gen.get_token()

    session = Session.builder.configs({
        "account": ACCOUNT.split(".")[0],  # <- sem .snowflakecomputing.com
        "user": USER.upper(),
        "authenticator": "SNOWFLAKE_JWT",  # <- valor correto!
        "token": token if isinstance(token, str) else token.decode(),
        "role": ROLE,
        "warehouse": WAREHOUSE,
        "database": DATABASE,
        "schema": SCHEMA,
    }).create()
    return session, jwt_gen

# ---------------------------------------------------------
# LISTA DE AGENTES
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
st.sidebar.write(f"**Usuário:** {USER}")
st.sidebar.write(f"**Warehouse:** {WAREHOUSE}")
st.sidebar.write(f"**Role:** {ROLE}")

# ---------------------------------------------------------
# HISTÓRICO DE CHAT
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
            token = jwt_gen.get_token()  # garante renovação automática
            session = Session.builder.configs({
                "account": ACCOUNT,
                "user": USER,
                "authenticator": "JWT",
                "token": token,
                "role": ROLE,
                "warehouse": WAREHOUSE,
                "database": DATABASE,
                "schema": SCHEMA,
            }).create()

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
