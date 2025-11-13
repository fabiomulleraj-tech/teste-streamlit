import streamlit as st
import requests
import time
import json
import base64
import hashlib
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------
# Forçar saída de iframe (Azure AD exige top-level window)
# ---------------------------------------------------------
st.markdown("""
<script>
if (window.top !== window.self) {
    window.top.location = window.location.href;
}
</script>
""", unsafe_allow_html=True)

st.set_page_config(page_title="Bentinho", page_icon="❄️", layout="wide")


# -----------------------------------------------------
# AUTENTICAÇÃO VIA AZURE AD — PKCE
# -----------------------------------------------------
AZ_CLIENT_ID = st.secrets["azure"]["client_id"]
AZ_TENANT_ID = st.secrets["azure"]["tenant_id"]
AZ_REDIRECT = st.secrets["azure"]["redirect_uri"]

AUTHORITY = f"https://login.microsoftonline.com/{AZ_TENANT_ID}"
AUTH_URL = f"{AUTHORITY}/oauth2/v2.0/authorize"
TOKEN_URL = f"{AUTHORITY}/oauth2/v2.0/token"
SCOPES = ["openid", "profile", "email"]

# -----------------------------------------------------
# PKCE FUNCTIONS
# -----------------------------------------------------
def generate_pkce_verifier():
    return base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()

def generate_pkce_challenge(verifier):
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

# -----------------------------------------------------
# LOGIN FLOW — PKCE ONLY
# -----------------------------------------------------
query_params = st.query_params
code = query_params.get("code", [None])[0]

if "auth_user" not in st.session_state:

    # Primeiro acesso — exibe botão de login
    if code is None:

        verifier = generate_pkce_verifier()
        challenge = generate_pkce_challenge(verifier)

        st.session_state.pkce_verifier = verifier

        login_url = (
            f"{AUTH_URL}"
            f"?client_id={AZ_CLIENT_ID}"
            f"&response_type=code"
            f"&redirect_uri={AZ_REDIRECT}"
            f"&response_mode=query"
            f"&scope={' '.join(SCOPES)}"
            f"&code_challenge={challenge}"
            f"&code_challenge_method=S256"
        )

        st.title("🔐 Login com Azure AD")
        st.markdown(
            f'<a href="{login_url}" target="_self">'
            f'<button style="font-size:20px;padding:10px 20px;">⭐ Entrar com Azure AD</button>'
            f'</a>',
            unsafe_allow_html=True
        )
        st.stop()

    # Retorno do Azure com /?code=123
    else:
        if "pkce_verifier" not in st.session_state:
            st.warning("Sessão expirada. Reinicie o login.")
            st.query_params.clear()
            st.rerun()

        data = {
            "grant_type": "authorization_code",
            "client_id": AZ_CLIENT_ID,
            "code": code,
            "redirect_uri": AZ_REDIRECT,
            "code_verifier": st.session_state.pkce_verifier,
        }

        resp = requests.post(TOKEN_URL, data=data)
        token_data = resp.json()

        if "id_token" not in token_data:
            st.error("❌ Erro ao obter token do Azure AD")
            st.write(token_data)
            st.stop()

        payload = token_data["id_token"].split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))

        st.session_state.auth_user = {
            "name": claims.get("name"),
            "email": claims.get("preferred_username"),
            "oid": claims.get("oid"),
        }

        # Limpa parâmetros da URL
        st.query_params.clear()

        st.rerun()

# ---------------------------------------------------------
# USUÁRIO LOGADO
# ---------------------------------------------------------
user = st.session_state.auth_user
st.sidebar.success(f"👤 {user['name']} ({user['email']})")


# ---------------------------------------------------------
# CONFIGURAÇÕES DO CORTEX + AGENTES
# ---------------------------------------------------------
ACCOUNT = "A6108453355571-ALMEIDAJR"
USER = "TEAMS_INTEGRATION"

AGENTS = {
    "🏬 Vendas e Faturamento": {"agent": "AJ_VS"},
    "📑 Contratos de Logistas": {"agent": "AJ_JURIDICO"},
    "🧾 Contratos de Fornecedores": {"agent": "AJ_PROTHEUS"},
}


# ---------------------------------------------------------
# JWTGenerator – autenticador Snowflake
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

        self.private_key_pem = key_text.encode()
        self.private_key = serialization.load_pem_private_key(
            self.private_key_pem, password=None, backend=default_backend()
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
        return self.token

    def get_token(self):
        if int(time.time()) >= self.renew_time:
            self.generate_token()
        return self.token


# ---------------------------------------------------------
# SSE – Streaming do Snowflake Cortex
# ---------------------------------------------------------
def send_prompt_to_cortex(prompt, agent, jwt):
    url = f"https://{ACCOUNT}.snowflakecomputing.com/api/v2/databases/SNOWFLAKE_INTELLIGENCE/schemas/AGENTS/agents/{agent}:run"

    headers = {
        "Authorization": f"Bearer {jwt}",
        "Accept": "text/event-stream",
        "Content-Type": "application/json",
    }

    body = {"messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}]}

    response = requests.post(url, headers=headers, json=body, stream=True)

    full = ""
    thinking = st.empty()
    chat = st.empty()

    for raw in response.iter_lines():
        if not raw:
            continue

        line = raw.decode().strip()
        if not line.startswith("data: "):
            continue

        data = json.loads(line[6:])

        if "thinking" in data:
            thinking.markdown(f"🧠 Pensando...\n```\n{data['thinking']}\n```")

        if "output" in data:
            full += data["output"]["text"]
            chat.markdown(full)

    thinking.empty()
    return full.strip()


# ---------------------------------------------------------
# HISTÓRICO DE CONVERSAS + TÍTULOS
# ---------------------------------------------------------
if "chat_history" not in st.session_state:
    st.session_state.chat_history = {}

if user["email"] not in st.session_state.chat_history:
    st.session_state.chat_history[user["email"]] = {}

if "chat_titles" not in st.session_state:
    st.session_state.chat_titles = {}

if user["email"] not in st.session_state.chat_titles:
    st.session_state.chat_titles[user["email"]] = {}


def new_chat_id():
    return f"chat_{int(time.time())}"


# Criar conversa inicial
if "current_chat_id" not in st.session_state:
    cid = new_chat_id()
    st.session_state.current_chat_id = cid
    st.session_state.chat_history[user["email"]][cid] = []
    st.session_state.chat_titles[user["email"]][cid] = "Novo Chat"


chat_id = st.session_state.current_chat_id
messages = st.session_state.chat_history[user["email"]][chat_id]


# Sidebar – Criar nova conversa
if st.sidebar.button("➕ Novo chat"):
    cid = new_chat_id()
    st.session_state.current_chat_id = cid
    st.session_state.chat_history[user["email"]][cid] = []
    st.session_state.chat_titles[user["email"]][cid] = "Novo Chat"
    st.rerun()


# Sidebar – Lista conversas
st.sidebar.markdown("### 💬 Suas conversas")
for cid, title in st.session_state.chat_titles[user["email"]].items():
    if st.sidebar.button(f"🗨️ {title}", key=f"chat_{cid}"):
        st.session_state.current_chat_id = cid
        st.rerun()


# ---------------------------------------------------------
# AGENTE SELECIONADO
# ---------------------------------------------------------
selected_agent = st.sidebar.selectbox(
    "Selecione o agente", list(AGENTS.keys())
)
agent_name = AGENTS[selected_agent]["agent"]


# ---------------------------------------------------------
# INICIALIZA JWT
# ---------------------------------------------------------
if "jwt" not in st.session_state:
    st.session_state.jwt = JWTGenerator(ACCOUNT, USER)

jwt_token = st.session_state.jwt.get_token()


# ---------------------------------------------------------
# RENDERIZA MENSAGENS DO CHAT
# ---------------------------------------------------------
for msg in messages:
    st.chat_message(msg["role"]).write(msg["content"])


# ---------------------------------------------------------
# CAIXA DE ENTRADA DO USUÁRIO
# ---------------------------------------------------------
prompt = st.chat_input("Digite sua pergunta...")

if prompt:

    # Se primeira mensagem → vira título do chat
    if len(messages) == 0:
        st.session_state.chat_titles[user["email"]][chat_id] = prompt[:50]

    messages.append({"role": "user", "content": prompt})
    st.chat_message("user").write(prompt)

    with st.spinner("Consultando o Cortex..."):
        resposta = send_prompt_to_cortex(prompt, agent_name, jwt_token)

    st.chat_message("assistant").write(resposta)
    messages.append({"role": "assistant", "content": resposta})
