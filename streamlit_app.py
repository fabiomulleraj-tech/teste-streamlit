import streamlit as st
import requests
import time
import json
import base64
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------
# CONFIGURAÇÕES BÁSICAS
# ---------------------------------------------------------
st.set_page_config(page_title="Snowflake Cortex Chat", page_icon="❄️", layout="wide")
st.title("🤖 Fale com o Betinho")

ACCOUNT = "A6108453355571-ALMEIDAJR"
USER = "TEAMS_INTEGRATION"
MODEL = "claude-3-5-sonnet"

AGENTS = {
    "🏬 Vendas e Shoppings (VS)": {"agent": "AJ_VS", "semantic_model": "AJ_SEMANTIC_VIEW_VS"},
    "📑 Jurídico (Contratos)": {"agent": "AJ_JURIDICO", "semantic_model": "AJ_SEMANTIC_JURIDICO"},
    "🧾 Protheus (Compras e Contratos)": {"agent": "AJ_PROTHEUS", "semantic_model": "AJ_SEMANTIC_PROTHEUS"},
}

ENDPOINT = f"https://{ACCOUNT}.snowflakecomputing.com/api/v2/databases/SNOWFLAKE_INTELLIGENCE/schemas/AGENTS/agents"

# ---------------------------------------------------------
# CLASSE JWTGenerator - 100% compatível com jwtGenerator.js
# ---------------------------------------------------------
class JWTGenerator:
    def __init__(self, account, user, key_path=None):
        self.account = account.upper()  # mantém o sufixo -ALMEIDAJR
        self.user = user.upper()
        self.qualified_username = f"{self.account}.{self.user}"
        self.lifetime = 3600
        self.renewal_delay = self.lifetime - 300

        # ---------------------------------------------------------
        # 1️⃣ Carrega a chave privada (do st.secrets ou arquivo)
        # ---------------------------------------------------------
        key_text = None
        if "rsa" in st.secrets and "private_key" in st.secrets["rsa"]:
            key_text = st.secrets["rsa"]["private_key"]
            key_text = key_text.replace("\\n", "\n").strip()
            if not key_text.startswith("-----BEGIN"):
                key_text = "-----BEGIN PRIVATE KEY-----\n" + key_text
            if not key_text.endswith("-----END PRIVATE KEY-----"):
                key_text += "\n-----END PRIVATE KEY-----"
            st.sidebar.success("🔐 Chave carregada do st.secrets")
        elif key_path:
            with open(key_path, "r") as f:
                key_text = f.read()
            st.sidebar.info(f"🔑 Chave lida do arquivo: {key_path}")
        else:
            raise ValueError("Nenhuma chave privada encontrada (nem em secrets, nem em arquivo).")

        self.private_key_pem = key_text.encode("utf-8")
        self.private_key = serialization.load_pem_private_key(
            self.private_key_pem, password=None, backend=default_backend()
        )
        st.sidebar.success("✅ Chave privada decodificada com sucesso.")

        # ---------------------------------------------------------
        # 2️⃣ Gera o fingerprint (SPKI DER → SHA256 Base64)
        # ---------------------------------------------------------
        self.public_fingerprint = self._calculate_public_key_fingerprint()
        st.sidebar.write(f"**Fingerprint:** `{self.public_fingerprint}`")

        # ---------------------------------------------------------
        # 3️⃣ Gera o primeiro JWT
        # ---------------------------------------------------------
        self.generate_token()

    # ---------------------------------------------------------
    # Cálculo idêntico ao Node: crypto.createPublicKey + export { type: "spki", format: "der" }
    # ---------------------------------------------------------
    def _calculate_public_key_fingerprint(self):
        public_key = self.private_key.public_key()
        der_public_key = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        sha256 = hashlib.sha256(der_public_key).digest()
        fingerprint = base64.b64encode(sha256).decode()
        return f"SHA256:{fingerprint}"

    # ---------------------------------------------------------
    # Geração do JWT idêntica ao jwtGenerator.js
    # ---------------------------------------------------------
    def generate_token(self):
        now = int(time.time())
        payload = {
            "iss": f"{self.qualified_username}.{self.public_fingerprint}",
            "sub": self.qualified_username,
            "iat": now,
            "exp": now + self.lifetime,
        }

        headers = {"alg": "RS256", "typ": "JWT"}

        def b64url(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).decode().rstrip("=")

        header_b64 = b64url(json.dumps(headers, separators=(",", ":")).encode())
        payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode())
        message = f"{header_b64}.{payload_b64}".encode()

        signature = self.private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        signature_b64 = b64url(signature)
        token = f"{header_b64}.{payload_b64}.{signature_b64}"

        # Debug visual completo
        st.sidebar.write("### 🧩 JWT Debug")
        st.sidebar.write(f"**iss:** {payload['iss']}")
        st.sidebar.write(f"**sub:** {payload['sub']}")
        st.sidebar.text_area("🪪 Token JWT Gerado", token, height=150)

        self.token = token
        self.renew_time = now + self.renewal_delay
        st.sidebar.success("✅ JWT gerado com sucesso.")
        return token

    # ---------------------------------------------------------
    def get_token(self):
        now = int(time.time())
        if now >= self.renew_time:
            st.sidebar.warning("♻️ Renovando JWT...")
            self.generate_token()
        return self.token


# ---------------------------------------------------------
# FUNÇÃO DE ENVIO AO CORTEX
# ---------------------------------------------------------
def send_prompt_to_cortex(prompt, model, agent, semantic_model, jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    url = f"{ENDPOINT}/{agent}:run"

    # ✅ Estrutura idêntica à usada no TeamsBot.js
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt}
                ]
            }
        ],
        "model": model,
        "parameters": {
            "semantic_model": semantic_model
        }
    }

    try:
        resp = requests.post(url, headers=headers, json=body, timeout=120)
        if resp.status_code == 200:
            data = resp.json()
            outputs = data.get("outputs", [])
            if outputs and "text" in outputs[0]:
                return outputs[0]["text"]
            return json.dumps(data, indent=2)
        else:
            return f"⚠️ Erro HTTP {resp.status_code}: {resp.text}"
    except Exception as e:
        return f"❌ Erro ao consultar o Cortex Agent: {e}"


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
