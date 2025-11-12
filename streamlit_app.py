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
st.sidebar.write("DEBUG KEY LENGTH:", len(st.secrets["rsa"]["private_key"]))
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
# GERADOR DE JWT
# ---------------------------------------------------------
class JWTGenerator:
    def __init__(self, account, user, key_path=None):
        self.account = self._prepare_account_name(account)
        self.user = user.upper()
        self.qualified_username = f"{self.account}.{self.user}"
        self.lifetime = 3600
        self.renewal_delay = self.lifetime - 300
        self.token = None
        self.renew_time = 0

        # 🔑 tenta carregar a chave do secrets primeiro
        if "rsa" in st.secrets and "private_key" in st.secrets["rsa"]:
            key_text = st.secrets["rsa"]["private_key"]

            # 🧹 Normaliza quebras de linha e remove caracteres ocultos
            key_text = key_text.replace("\r", "").replace("\\n", "\n").strip()
            key_text = "\n".join(line.strip() for line in key_text.splitlines() if line.strip())

            # 🔒 Garante delimitadores válidos
            if not key_text.startswith("-----BEGIN PRIVATE KEY-----"):
                key_text = "-----BEGIN PRIVATE KEY-----\n" + key_text
            if not key_text.endswith("-----END PRIVATE KEY-----"):
                key_text = key_text + "\n-----END PRIVATE KEY-----"

            # 🔧 Converte para bytes limpos e força UTF-8 sem BOM
            self.private_key_pem = key_text.encode("utf-8").strip()
            st.sidebar.success("🔐 Chave carregada do st.secrets")
        else:
            raise ValueError("Nenhuma chave privada encontrada (nem em secrets, nem em arquivo).")

        # ----------------------------- #
        # Decodifica chave PEM em objeto
        # ----------------------------- #
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        try:
            self.private_key = serialization.load_pem_private_key(
                data=self.private_key_pem,
                password=None,
                backend=default_backend()
            )

            # 🔎 Verifica se realmente carregou um objeto válido
            if self.private_key is None:
                raise ValueError("load_pem_private_key retornou None — formato PEM inválido.")
            else:
                st.sidebar.write("✅ Chave privada decodificada com sucesso.")
        except Exception as e:
            st.error(f"Erro ao decodificar chave privada: {e}")
            raise


        # Calcula fingerprint
        import hashlib, base64
        public_key = self.private_key.public_key()
        der_pub = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        sha256_digest = hashlib.sha256(der_pub).digest()
        self.public_fingerprint = f"SHA256:{base64.b64encode(sha256_digest).decode('utf-8')}"

        # Gera token inicial
        self.generate_token()

    # 🔧 método auxiliar
    def _prepare_account_name(self, raw_account):
        if ".global" in raw_account:
            return raw_account.split("-")[0].upper()
        return raw_account.split(".")[0].upper()

    def generate_token(self):
        now = int(time.time())
        payload = {
            "iss": f"{self.qualified_username}.{self.public_fingerprint}",
            "sub": self.qualified_username,
            "iat": now,
            "exp": now + self.lifetime,
        }

        # Garante que a chave seja um objeto RSAPrivateKey
        private_key_obj = self.private_key
        if private_key_obj is None:
            raise ValueError("Chave privada inválida.")

        self.token = jwt.encode(payload, self.private_key_pem, algorithm="RS256")
        self.renew_time = now + self.renewal_delay
        return self.token

    def get_token(self):
        now = int(time.time())
        if now >= self.renew_time:
            st.sidebar.warning("♻️ Regenerando JWT...")
            self.generate_token()
        return self.token


# ---------------------------------------------------------
# CRIA E MANTÉM A SESSÃO SNOWFLAKE
# ---------------------------------------------------------
def create_session():
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
