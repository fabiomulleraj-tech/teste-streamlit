import streamlit as st
import requests
import time
import jwt
import base64
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------
# CONFIGURAÇÕES BÁSICAS
# ---------------------------------------------------------
st.set_page_config(page_title="Snowflake Cortex Chat", page_icon="❄️", layout="wide")
st.title("🤖 Chat com Agentes de IA - Snowflake Cortex")

ACCOUNT = "A6108453355571-ALMEIDAJR"
USER = "TEAMS_INTEGRATION"
MODEL = "snowflake-arctic"
AGENTS = {
    "📑 Jurídico (Contratos)": {
        "agent": "AJ_JURIDICO",
        "semantic_model": "AJ_SEMANTIC_JURIDICO",
    },
    "🏬 Vendas e Shoppings (VS)": {
        "agent": "AJ_VS",
        "semantic_model": "AJ_SEMANTIC_VIEW_VS",
    },
    "🧾 Protheus (Compras e Contratos)": {
        "agent": "AJ_PROTHEUS",
        "semantic_model": "AJ_SEMANTIC_PROTHEUS",
    },
}
ENDPOINT = f"https://{ACCOUNT}.snowflakecomputing.com/api/v2/databases/SNOWFLAKE_INTELLIGENCE/schemas/AGENTS/agents"

# ---------------------------------------------------------
# CLASSE JWTGenerator - mesma lógica do teamsBot.js
# ---------------------------------------------------------
class JWTGenerator:
    def __init__(self, account, user, key_path=None):
        self.account = self._prepare_account_name(account)
        self.user = user.upper()
        self.lifetime = 3600  # 1h
        self.renewal_delay = self.lifetime - 300
        self.token = None
        self.renew_time = 0
        self.private_key_pem = self._load_key()
        self.private_key = serialization.load_pem_private_key(
            self.private_key_pem.encode(), password=None, backend=default_backend()
        )
        self.public_fingerprint = self._calc_fingerprint()
        self.generate_token()

    def _load_key(self):
        if "rsa" in st.secrets and "private_key" in st.secrets["rsa"]:
            key_text = st.secrets["rsa"]["private_key"]
            key_text = key_text.replace("\r", "").replace("\\n", "\n").strip()
            if not key_text.startswith("-----BEGIN"):
                key_text = "-----BEGIN PRIVATE KEY-----\n" + key_text
            if not key_text.endswith("-----END PRIVATE KEY-----"):
                key_text += "\n-----END PRIVATE KEY-----"
            st.sidebar.success("🔐 Chave carregada do st.secrets")
            return key_text
        raise ValueError("❌ Nenhuma chave RSA encontrada no st.secrets")

    def _calc_fingerprint(self):
        public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        sha256_digest = hashlib.sha256(public_key).digest()
        return f"SHA256:{base64.b64encode(sha256_digest).decode()}"
    
    def _prepare_account_name(self, raw_account):
        return raw_account.split("-")[0].split(".")[0].upper()
    
    def generate_token(self):
        now = int(time.time())
        payload = {
            "iss": f"{self.account}.{self.user}.{self.public_fingerprint}",
            "sub": f"{self.account}.{self.user}",
            "iat": now,
            "exp": now + self.lifetime,
        }
        self.token = jwt.encode(payload, self.private_key_pem, algorithm="RS256")
        self.renew_time = now + self.renewal_delay
        st.sidebar.success("✅ JWT gerado com sucesso.")
        return self.token

    def get_token(self):
        now = int(time.time())
        if now >= self.renew_time:
            st.sidebar.warning("♻️ Renovando JWT...")
            self.generate_token()
        return self.token


# ---------------------------------------------------------
# FUNÇÃO PARA ENVIAR PROMPT AO CORTEX
# ---------------------------------------------------------
def send_prompt_to_cortex(prompt: str, model: str, agent: str, semantic_model: str, jwt_token: str):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    url = f"{ENDPOINT}/{agent}:run"
    body = {"inputs": {"question": prompt, "semantic_model": semantic_model}}

    try:
        resp = requests.post(url, headers=headers, json=body, timeout=120)
        if resp.status_code == 200:
            data = resp.json()
            outputs = data.get("outputs", [])
            if outputs and "text" in outputs[0]:
                return outputs[0]["text"]
            return str(data)
        else:
            return f"⚠️ Erro HTTP {resp.status_code}: {resp.text}"
    except Exception as e:
        return f"❌ Erro na requisição ao Cortex Agent: {e}"


# ---------------------------------------------------------
# INICIALIZA JWT E CHAT
# ---------------------------------------------------------
if "jwt_gen" not in st.session_state:
    st.session_state.jwt_gen = JWTGenerator(ACCOUNT, USER)
jwt_gen = st.session_state.jwt_gen
jwt_token = jwt_gen.get_token()

# ---------------------------------------------------------
# SIDEBAR - seleção de agente
# ---------------------------------------------------------
st.sidebar.header("⚙️ Configurações")
selected_agent = st.sidebar.selectbox("Selecione o agente de IA:", list(AGENTS.keys()))
agent_cfg = AGENTS[selected_agent]
agent_name = agent_cfg["agent"]
semantic_model = agent_cfg["semantic_model"]
st.sidebar.markdown("---")
st.sidebar.write(f"**Usuário:** {USER}")
st.sidebar.write(f"**Conta:** {ACCOUNT}")
st.sidebar.write(f"**Fingerprint:** `{jwt_gen.public_fingerprint[:40]}...`")
st.sidebar.write(f"**Renovação:** {time.strftime('%H:%M:%S', time.localtime(jwt_gen.renew_time))}")

# ---------------------------------------------------------
# HISTÓRICO DE CHAT
# ---------------------------------------------------------
if "messages" not in st.session_state:
    st.session_state.messages = []

for msg in st.session_state.messages:
    st.chat_message(msg["role"]).write(msg["content"])

# ---------------------------------------------------------
# INPUT DO USUÁRIO
# ---------------------------------------------------------
prompt = st.chat_input("Digite sua pergunta...")

if prompt:
    st.session_state.messages.append({"role": "user", "content": prompt})
    st.chat_message("user").write(prompt)

    with st.spinner(f"Consultando agente {selected_agent}..."):
        resposta = send_prompt_to_cortex(prompt, MODEL, agent_name, semantic_model, jwt_token)

    st.chat_message("assistant").write(resposta)
    st.session_state.messages.append({"role": "assistant", "content": resposta})
