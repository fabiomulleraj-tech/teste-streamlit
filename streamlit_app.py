import streamlit as st
import requests
import time
import json
import base64
import hashlib
import sseclient
import io
import msal
import urllib.parse
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------
# Configuração principal da página (DEVE SER A PRIMEIRA CHAMADA)
# ---------------------------------------------------------
st.set_page_config(page_title="Bentinho", page_icon="❄️", layout="wide")

# ---------------------------------------------------------
# LOGIN SIMPLES
# ---------------------------------------------------------
USERS = st.secrets["auth"]

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    st.title("🔐 Login necessário")
    username = st.text_input("Usuário")
    password = st.text_input("Senha", type="password")

    if st.button("Entrar"):
        if username in USERS and USERS[username] == password:
            st.session_state.logged_in = True
            st.session_state.user = username
            st.success(f"✅ Bem-vindo, {username}!")
            st.rerun()
        else:
            st.error("❌ Usuário ou senha inválidos.")
    st.stop()

st.sidebar.success(f"👤 Usuário: {st.session_state.user}")


# ---------------------------------------------------------
# CONFIGURAÇÕES DO CORTEX
# ---------------------------------------------------------
st.title("💁‍♂️ Pergunte ao Bentinho")
st.caption("Não esqueça de selecionar a área que deseja a informação ao lado 👈")

ACCOUNT = "A6108453355571-ALMEIDAJR"
USER = "TEAMS_INTEGRATION"

AGENTS = {
    "🏬 Vendas e Faturamento": {"agent": "AJ_VS"},
    "📑 Contratos de Logistas": {"agent": "AJ_JURIDICO"},
    "🧾 Contratos de Fornecedores": {"agent": "AJ_PROTHEUS"},
}

# ---------------------------------------------------------
# JWTGenerator
# ---------------------------------------------------------
class JWTGenerator:
    def __init__(self, account, user):
        self.account = account.upper()
        self.user = user.upper()
        self.qualified_username = f"{self.account}.{self.user}"
        self.lifetime = 3600
        self.renewal_delay = self.lifetime - 300

        key_text = st.secrets["rsa"]["private_key"].replace("\\n", "\n").strip()
        if not key_text.startswith("-----BEGIN"):
            key_text = "-----BEGIN PRIVATE KEY-----\n" + key_text
        if not key_text.endswith("-----END PRIVATE KEY-----"):
            key_text += "\n-----END PRIVATE KEY-----"

        self.private_key = serialization.load_pem_private_key(
            key_text.encode(), password=None, backend=default_backend()
        )

        self.public_fingerprint = self._fingerprint()
        self.generate_token()

    def _fingerprint(self):
        der = self.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        sha = hashlib.sha256(der).digest()
        return f"SHA256:{base64.b64encode(sha).decode()}"

    def generate_token(self):
        now = int(time.time())
        payload = {
            "iss": f"{self.qualified_username}.{self.public_fingerprint}",
            "sub": self.qualified_username,
            "iat": now,
            "exp": now + self.lifetime,
        }

        def b64(data):
            return base64.urlsafe_b64encode(data).decode().rstrip("=")

        header = b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        body = b64(json.dumps(payload).encode())
        msg = f"{header}.{body}".encode()

        sig = self.private_key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        self.token = f"{header}.{body}.{b64(sig)}"
        self.renew_time = now + self.renewal_delay

    def get_token(self):
        if int(time.time()) >= self.renew_time:
            self.generate_token()
        return self.token


# ---------------------------------------------------------
# SSE - Streaming Cortex
# ---------------------------------------------------------
def send_prompt_to_cortex(prompt, agent, jwt_token, debug=False):
    url = f"https://{ACCOUNT}.snowflakecomputing.com/api/v2/databases/SNOWFLAKE_INTELLIGENCE/schemas/AGENTS/agents/{agent}:run"

    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "text/event-stream",
        "Content-Type": "application/json",
    }

    body = {"messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}]}

    try:
        with requests.post(url, headers=headers, json=body, stream=True, timeout=180) as resp:
            if resp.status_code != 200:
                return f"⚠️ Erro HTTP {resp.status_code}: {resp.text}"

            full_text = ""
            thinking_box = st.empty()
            chat_box = st.empty()

            for raw_line in resp.iter_lines():
                if not raw_line:
                    continue

                line = raw_line.decode().strip()
                if not line.startswith("data: "):
                    continue

                data = json.loads(line[len("data: "):])

                if "thinking" in data:
                    thinking_box.markdown(f"🧠 **Pensando...**\n```\n{data['thinking']}\n```")

                if "output" in data:
                    full_text += data["output"].get("text", "")
                    chat_box.markdown(full_text)

            thinking_box.empty()
            return full_text.strip()

    except Exception as e:
        return f"❌ Erro ao consultar o agente: {e}"


# ---------------------------------------------------------
# INICIALIZA JWT
# ---------------------------------------------------------
if "jwt_gen" not in st.session_state:
    st.session_state.jwt_gen = JWTGenerator(ACCOUNT, USER)

jwt_gen = st.session_state.jwt_gen
jwt_token = jwt_gen.get_token()


# ---------------------------------------------------------
# SIDEBAR — seleção do agente
# ---------------------------------------------------------
selected_agent = st.sidebar.selectbox("Selecione o agente de IA:", list(AGENTS.keys()))
agent_name = AGENTS[selected_agent]["agent"]

# ---------------------------------------------------------
# HISTÓRICO DE CHAT
# ---------------------------------------------------------
if "messages" not in st.session_state:
    st.session_state.messages = []

for msg in st.session_state.messages:
    st.chat_message(msg["role"]).write(msg["content"])

# ---------------------------------------------------------
# ENTRADA DO USUÁRIO
# ---------------------------------------------------------
prompt = st.chat_input("Digite sua pergunta...")

if prompt:
    st.session_state.messages.append({"role": "user", "content": prompt})
    st.chat_message("user").write(prompt)

    with st.spinner(f"Consultando agente {selected_agent}..."):
        resposta = send_prompt_to_cortex(prompt, agent_name, jwt_token)

    st.chat_message("assistant").write(resposta)
    st.session_state.messages.append({"role": "assistant", "content": resposta})
