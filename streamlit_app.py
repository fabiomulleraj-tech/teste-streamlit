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
        self.qualified_username = f"{self.account}.{self.user}"
        self.lifetime = 3600  # 1 hora
        self.renewal_delay = self.lifetime - 300  # renova 5 min antes

        # ---------------------------------------------------------
        # 1️⃣ Carrega a chave privada (do st.secrets ou de arquivo)
        # ---------------------------------------------------------
        key_text = None

        # 🔹 Preferência: st.secrets["rsa"]["private_key"]
        if "rsa" in st.secrets and "private_key" in st.secrets["rsa"]:
            key_text = st.secrets["rsa"]["private_key"]
            key_text = key_text.replace("\\n", "\n").strip()
            if not key_text.startswith("-----BEGIN"):
                key_text = "-----BEGIN PRIVATE KEY-----\n" + key_text
            if not key_text.endswith("-----END PRIVATE KEY-----"):
                key_text += "\n-----END PRIVATE KEY-----"
            st.sidebar.success("🔐 Chave carregada do st.secrets")

        # 🔹 Alternativa: arquivo físico (rsa_key.p8)
        elif key_path:
            with open(key_path, "r") as f:
                key_text = f.read()
            st.sidebar.info(f"🔑 Chave lida do arquivo: {key_path}")

        # 🔹 Nenhuma chave encontrada
        else:
            raise ValueError("Nenhuma chave privada encontrada (nem em secrets, nem em arquivo).")

        # ---------------------------------------------------------
        # 2️⃣ Converte e carrega a chave privada
        # ---------------------------------------------------------
        self.private_key_pem = key_text.encode("utf-8")
        self.private_key = serialization.load_pem_private_key(
            self.private_key_pem, password=None, backend=default_backend()
        )
        st.sidebar.success("✅ Chave privada decodificada com sucesso.")

        # ---------------------------------------------------------
        # 3️⃣ Calcula fingerprint e gera token inicial
        # ---------------------------------------------------------
        self.public_fingerprint = self._calc_fingerprint()
        self.generate_token()


    def _prepare_account_name(self, raw_account):
        return raw_account.split("-")[0].split(".")[0].upper()

    def _calc_fingerprint(self):
        public_key = serialization.load_pem_private_key(
            self.private_key_pem, password=None, backend=default_backend()
        ).public_key()
        der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        sha256 = hashlib.sha256(der).digest()
        return f"SHA256:{base64.b64encode(sha256).decode()}"

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
