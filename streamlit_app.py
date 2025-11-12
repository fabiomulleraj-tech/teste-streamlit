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
# GERADOR DE JWT (corrigido e completo)
# ---------------------------------------------------------
class JWTGenerator:
    def __init__(self, account, user, key_path=None):
        self.account = self._prepare_account_name(account)
        self.user = user.upper()
        self.qualified_username = f"{self.account}.{self.user}"
        self.lifetime = 3600  # 1h
        self.renewal_delay = self.lifetime - 300  # renova 5min antes

        # 🔑 tenta carregar a chave do secrets primeiro
        if "rsa" in st.secrets and "private_key" in st.secrets["rsa"]:
            self.private_key_pem = st.secrets["rsa"]["private_key"].encode()
            st.sidebar.success("🔐 Chave carregada do st.secrets")
        elif key_path:
            self.private_key_pem = open(key_path, "rb").read()
            st.sidebar.info(f"🔑 Chave lida de arquivo: {key_path}")
        else:
            raise ValueError("Nenhuma chave privada encontrada (nem em secrets, nem em arquivo).")

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        self.private_key = serialization.load_pem_private_key(
            self.private_key_pem, password=None, backend=default_backend()
        )

        import hashlib, base64
        public_key = self.private_key.public_key()
        der_pub = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        sha256_digest = hashlib.sha256(der_pub).digest()
        self.public_fingerprint = f"SHA256:{base64.b64encode(sha256_digest).decode('utf-8')}"

        self.token = None
        self.renew_time = 0
        self.generate_token()

    # 🔧 método que estava faltando
    def _prepare_account_name(self, raw_account):
        if ".global" in raw_account:
            return raw_account.split("-")[0].upper()
        return raw_account.split(".")[0].upper()

    def generate_token(self):
        import time, jwt
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
        import time
        now = int(time.time())
        if now >= self.renew_time:
            st.sidebar.warning("♻️ Regenerando JWT...")
            self.generate_token()
        return self.token


# ---------------------------------------------------------
# CRIAR E MANTER SESSÃO SNOWFLAKE COM RENOVAÇÃO DE JWT
# ---------------------------------------------------------
def create_session():
    """Cria uma sessão Snowflake com token JWT válido."""
    try:
        if "jwt_gen" not in st.session_state:
            st.session_state.jwt_gen = JWTGenerator(ACCOUNT, USER, RSA_KEY_PATH)

        jwt_gen = st.session_state.jwt_gen
        token = jwt_gen.get_token()

        session = Session.builder.configs({
            "account": ACCOUNT,
            "user": USER,
            "authenticator": "SNOWFLAKE_JWT",
            "token": token if isinstance(token, str) else token.decode(),
            "role": ROLE,
            "warehouse": WAREHOUSE,
            "database": DATABASE,
            "schema": SCHEMA,
        }).create()

        st.session_state.session = session
        return session

    except Exception as e:
        st.error(f"❌ Falha ao conectar ao Snowflake: {e}")
        st.stop()


# ---------------------------------------------------------
# GARANTE SESSÃO ATIVA
# ---------------------------------------------------------
if "session" not in st.session_state:
    session = create_session()
else:
    session = st.session_state.session
    # se a sessão for perdida, recria
    try:
        session.sql("SELECT 1").collect()
    except Exception:
        st.warning("⚠️ Sessão expirada. Recriando conexão...")
        session = create_session()
if "jwt_gen" in st.session_state:
    jwt_gen = st.session_state.jwt_gen
    st.sidebar.markdown("### 🔐 Status do Token")
    st.sidebar.write(f"Fingerprint: `{jwt_gen.public_fingerprint[:40]}...`")
    st.sidebar.write(f"Renovação em: {time.strftime('%H:%M:%S', time.localtime(jwt_gen.renew_time))}")

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
            session = st.session_state.session  # sempre usa a sessão ativa
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
