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
SEMANTIC_MODELS = {
    "📑 Jurídico (Contratos)": "AJ_JURIDICO_CONTRATOS",
    "🏬 Vendas e Shoppings (VS)": "AJ_SEMANTIC_VIEW_VS",
    "🧾 Protheus (Compras e Contratos)": "AJ_SEMANTIC_PROTHEUS",
    "⚙️ Supply Chain": "AJ_SUPPLY_CHAIN",
}
ENDPOINT = f"https://{ACCOUNT}.snowflakecomputing.com/api/v2/cortex/chat/completions"

# ---------------------------------------------------------
# CLASSE JWTGenerator - mesma lógica do teamsBot.js
# ---------------------------------------------------------
class JWTGenerator:
    def __init__(self, account, user):
        self.account = account.split(".")[0].upper()
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
def send_prompt_to_cortex(prompt: str, model: str, semantic_model: str, jwt_token: str):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    body = {
        "model": model,
        "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}],
        "tools": [{"tool_spec": {"type": "cortex_analyst_text_to_sql", "name": "data_model"}}],
        "tool_resources": {"data_model": {"semantic_view": semantic_model}},
    }
    try:
        resp = requests.post(ENDPOINT, headers=headers, json=body, timeout=120)
        if resp.status_code == 200:
            data = resp.json()
            # Cortex retorna o texto dentro de choices[0].message.content[0].text
            return (
                data.get("choices", [{}])[0]
                .get("message", {})
                .get("content", [{}])[0]
                .get("text", "⚠️ Resposta vazia do agente.")
            )
        else:
            return f"⚠️ Erro HTTP {resp.status_code}: {resp.text}"
    except Exception as e:
        return f"❌ Erro na requisição ao Cortex: {e}"


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
selected_agent = st.sidebar.selectbox("Selecione o agente de IA:", list(SEMANTIC_MODELS.keys()))
semantic_model = SEMANTIC_MODELS[selected_agent]
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
        resposta = send_prompt_to_cortex(prompt, MODEL, semantic_model, jwt_token)

    st.chat_message("assistant").write(resposta)
    st.session_state.messages.append({"role": "assistant", "content": resposta})
