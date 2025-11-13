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

st.set_page_config(page_title="Bentinho", page_icon="❄️", layout="wide")
# ---------------------------------------------------------
# AUTENTICAÇÃO VIA AZURE AD
# ---------------------------------------------------------
AZ_CLIENT_ID = st.secrets["azure"]["client_id"]
AZ_TENANT_ID = st.secrets["azure"]["tenant_id"]
AZ_CLIENT_SECRET = st.secrets["azure"]["client_secret"]
AZ_REDIRECT = st.secrets["azure"]["redirect_uri"]

AUTHORITY = f"https://login.microsoftonline.com/{AZ_TENANT_ID}"

def build_msal_app():
    return msal.ConfidentialClientApplication(
        client_id=AZ_CLIENT_ID,
        authority=AUTHORITY,
        client_credential=AZ_CLIENT_SECRET,
    )

def build_auth_url():
    return build_msal_app().get_authorization_request_url(
        scopes=[],                 
        redirect_uri=AZ_REDIRECT
    )

# ---------------------------------------------------------
# FLUXO DE LOGIN
# ---------------------------------------------------------
query_params = st.query_params

if "auth_user" not in st.session_state:
    if "code" not in query_params:
        st.title("🔐 Login com Azure AD")
        st.markdown("Clique abaixo para autenticar com sua conta corporativa.")

        login_url = build_auth_url()

        if st.button("⭐ Entrar com Azure AD"):
            st.markdown(
                f"<script>window.location.href='{login_url}';</script>",
                unsafe_allow_html=True
            )
        st.stop()
    else:
        code = query_params["code"]

        app = build_msal_app()
        result = app.acquire_token_by_authorization_code(
            code,
            scopes=[],               
            redirect_uri=AZ_REDIRECT
        )

        if "id_token_claims" in result:
            claims = result["id_token_claims"]

            st.session_state.auth_user = {
                "name": claims.get("name"),
                "email": claims.get("preferred_username"),
                "oid": claims.get("oid"),
            }

            st.rerun()
        else:
            st.error("❌ Falha ao autenticar no Azure AD")
            st.stop()

user_email = st.session_state.auth_user["email"]

# ---------------------------------------------------------
# HISTÓRICO DE CHAT POR USUÁRIO + TÍTULOS
# ---------------------------------------------------------
def new_chat_id():
    return f"chat_{int(time.time())}"

if "chat_history" not in st.session_state:
    st.session_state.chat_history = {}

if "chat_titles" not in st.session_state:
    st.session_state.chat_titles = {}  # título por chat

if user_email not in st.session_state.chat_history:
    st.session_state.chat_history[user_email] = {}

if user_email not in st.session_state.chat_titles:
    st.session_state.chat_titles[user_email] = {}

if "current_chat_id" not in st.session_state:
    cid = new_chat_id()
    st.session_state.current_chat_id = cid
    st.session_state.chat_history[user_email][cid] = []
    st.session_state.chat_titles[user_email][cid] = "Novo Chat"

chat_id = st.session_state.current_chat_id
messages = st.session_state.chat_history[user_email][chat_id]

# ---------------------------------------------------------
# SIDEBAR + NOVA CONVERSA + LISTA DE CONVERSAS
# ---------------------------------------------------------
st.sidebar.header("👤 Usuário:")
st.sidebar.write(f"{st.session_state.auth_user['name']}")
st.sidebar.write(f"({st.session_state.auth_user['email']})")

if st.sidebar.button("➕ Nova conversa"):
    cid = new_chat_id()
    st.session_state.current_chat_id = cid
    st.session_state.chat_history[user_email][cid] = []
    st.session_state.chat_titles[user_email][cid] = "Novo Chat"
    st.rerun()

st.sidebar.markdown("### 💬 Suas conversas:")

for cid, title in st.session_state.chat_titles[user_email].items():
    label = f"🗨️ {title}"
    if st.sidebar.button(label, key=f"chatbtn_{cid}"):
        st.session_state.current_chat_id = cid
        st.rerun()

# ---------------------------------------------------------
# CONFIGURAÇÕES BÁSICAS
# ---------------------------------------------------------


st.title("💁‍♂️ Pergunte ao Bentinho")
st.caption("Não esqueça de selecionar a área que deseja a informação ao lado 👈")

ACCOUNT = "A6108453355571-ALMEIDAJR"
USER = "TEAMS_INTEGRATION"
MODEL = "claude-3-5-sonnet"

AGENTS = {
    "🏬 Vendas e Faturamento": {"agent": "AJ_VS", "semantic_model": "AJ_SEMANTIC_VIEW_VS"},
    "📑 Contratos de Logistas": {"agent": "AJ_JURIDICO", "semantic_model": "AJ_SEMANTIC_JURIDICO"},
    "🧾 Contratos de Fornecedores": {"agent": "AJ_PROTHEUS", "semantic_model": "AJ_SEMANTIC_PROTHEUS"},
}

ENDPOINT = f"https://{ACCOUNT}.snowflakecomputing.com/api/v2/databases/SNOWFLAKE_INTELLIGENCE/schemas/AGENTS/agents"

# ---------------------------------------------------------
# JWTGenerator – compatível com jwtGenerator.js
# ---------------------------------------------------------
class JWTGenerator:
    def __init__(self, account, user, key_path=None):
        self.account = account.upper()
        self.user = user.upper()
        self.qualified_username = f"{self.account}.{self.user}"
        self.lifetime = 3600
        self.renewal_delay = self.lifetime - 300

        key_text = None
        if "rsa" in st.secrets and "private_key" in st.secrets["rsa"]:
            key_text = st.secrets["rsa"]["private_key"]
            key_text = key_text.replace("\\n", "\n").strip()
            if not key_text.startswith("-----BEGIN"):
                key_text = "-----BEGIN PRIVATE KEY-----\n" + key_text
            if not key_text.endswith("-----END PRIVATE KEY-----"):
                key_text += "\n-----END PRIVATE KEY-----"
        elif key_path:
            with open(key_path, "r") as f:
                key_text = f.read()
        else:
            raise ValueError("Nenhuma chave privada encontrada.")

        self.private_key_pem = key_text.encode("utf-8")
        self.private_key = serialization.load_pem_private_key(
            self.private_key_pem, password=None, backend=default_backend()
        )

        self.public_fingerprint = self._calculate_public_key_fingerprint()

        self.generate_token()

    def _calculate_public_key_fingerprint(self):
        public_key = self.private_key.public_key()
        der_public_key = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        sha256 = hashlib.sha256(der_public_key).digest()
        fingerprint = base64.b64encode(sha256).decode()
        return f"SHA256:{fingerprint}"

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

        self.token = f"{header_b64}.{payload_b64}.{signature_b64}"
        self.renew_time = now + self.renewal_delay
        return self.token

    def get_token(self):
        now = int(time.time())
        if now >= self.renew_time:
            self.generate_token()
        return self.token

# ---------------------------------------------------------
# STREAMING SSE — Cortex
# ---------------------------------------------------------
def send_prompt_to_cortex(prompt, agent, jwt_token, debug=False):
    url = f"https://{ACCOUNT}.snowflakecomputing.com/api/v2/databases/SNOWFLAKE_INTELLIGENCE/schemas/AGENTS/agents/{agent}:run"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "text/event-stream",
        "Content-Type": "application/json",
    }

    body = {
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": prompt}]}
        ]
    }

    if debug:
        with st.expander("🧩 DEBUG REQUEST", expanded=False):
            st.write("**URL:**", url)
            st.json(headers)
            st.json(body)
            st.code(jwt_token)

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
                try:
                    line = raw_line.decode("utf-8").strip()
                    if line.startswith("data: "):
                        data = json.loads(line[len("data: "):])

                        if "thinking" in data:
                            thinking_box.markdown(
                                f"🧠 **Pensando...**\n\n```\n{data['thinking']}\n```"
                            )

                        if "output" in data:
                            full_text += data["output"].get("text", "")
                            chat_box.markdown(full_text)

                except Exception:
                    pass

            thinking_box.empty()
            return full_text.strip() or "⚠️ Nenhum conteúdo retornado."

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
# SIDEBAR – seleção de agente
# ---------------------------------------------------------
st.sidebar.header("⚙️ Selecione o agente")
selected_agent = st.sidebar.selectbox(
    "Selecione o agente de IA:",
    list(AGENTS.keys()),
    label_visibility="collapsed"
)
agent_cfg = AGENTS[selected_agent]
agent_name = agent_cfg["agent"]

# ---------------------------------------------------------
# RENDERIZA O HISTÓRICO
# ---------------------------------------------------------
for msg in messages:
    st.chat_message(msg["role"]).write(msg["content"])

# ---------------------------------------------------------
# INPUT DO USUÁRIO + RENOMEAÇÃO DO CHAT
# ---------------------------------------------------------
prompt = st.chat_input("Digite sua pergunta...")

if prompt:

    # Se é a primeira mensagem, o título vira a pergunta
    if len(st.session_state.chat_history[user_email][chat_id]) == 0:
        st.session_state.chat_titles[user_email][chat_id] = prompt[:50]

    st.session_state.chat_history[user_email][chat_id].append(
        {"role": "user", "content": prompt}
    )
    st.chat_message("user").write(prompt)

    with st.spinner(f"Consultando agente {selected_agent}..."):
        resposta = send_prompt_to_cortex(prompt, agent_name, jwt_token, debug=True)

    st.chat_message("assistant").write(resposta)

    st.session_state.chat_history[user_email][chat_id].append(
        {"role": "assistant", "content": resposta}
    )
