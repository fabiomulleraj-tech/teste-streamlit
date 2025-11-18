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
import ssl
import datetime
import extra_streamlit_components as stx
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from ldap3 import Server, Connection, ALL, SIMPLE, Tls


st.set_page_config(page_title="Bentinho", page_icon="❄️", layout="wide")
#@st.cache_resource(suppress_st_warning=True)
def get_manager():
    return stx.CookieManager()

cookie_manager = get_manager()

st.subheader("All Cookies:")
cookies = cookie_manager.get_all()
st.write(cookies)

#st.session_state.setdefault("logged_in", False)
#st.session_state.setdefault("username", None)

# ---------------------------------------------------------
# SESSION INITIALIZATION
# ---------------------------------------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "username" not in st.session_state:
    st.session_state.username = None

# ---------------------------------------------------------
# AD SERVERS
# ---------------------------------------------------------
AD_SERVERS = [
    "ldaps://SRVADPRD.central.local:636",
    "ldaps://SRVADPRD2.central.local:636"
]

def authenticate_ad(username, password):
    user_dn = f"CENTRAL\\{username}"

    tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)

    last_error = ""

    for srv in AD_SERVERS:
        try:
            server = Server(srv, use_ssl=True, get_info=ALL, tls=tls)
            conn = Connection(server, user=user_dn, password=password, authentication=SIMPLE, auto_bind=True)
            conn.unbind()
            return True
        except Exception as e:
            last_error = str(e)

    st.error(f"Falha AD: {last_error}")
    return False

# ----- LOGIN VIA COOKIE -----

saved_user = cookie_manager.get("aj_logged_user")

if saved_user and not st.session_state.logged_in:
    st.session_state.logged_in = True
    st.session_state.username = saved_user

# ---------------------------------------------------------
# LOGIN PAGE
# ---------------------------------------------------------
if not st.session_state.logged_in:
    st.title("🔐 Login (Active Directory)")

    username = st.text_input("Usuário (sem domínio)")
    password = st.text_input("Senha", type="password")

    if st.button("Entrar"):
        if authenticate_ad(username, password):
            # cria cookie persistente
            expires = datetime.now() + timedelta(minutes=10)
            cookie_manager.set("aj_logged_user", username, expires_at=expires)

            st.session_state.logged_in = True
            st.session_state.username = username

            st.success("✅ Autenticado com sucesso!")
            st.rerun()
        else:
            st.error("❌ Usuário ou senha inválidos.")

    st.stop()   # impede renderização do restante da página


# ---------------------------------------------------------
# USER LOGGED — NORMAL APP EXECUTION
# ---------------------------------------------------------
st.sidebar.success(f"👤 Logado como: {st.session_state.username}")

if st.sidebar.button("Sair"):
    if cookie_manager.get("aj_logged_user") is not None:
        cookie_manager.delete("aj_logged_user")
    st.session_state.logged_in = False
    st.session_state.username = None
    st.rerun()
   
st.sidebar.success("📌 Cookie detectado:", cookie_manager.get("aj_logged_user"))



# ---------------------------------------------------------
# CONFIGURAÇÕES BÁSICAS
# ---------------------------------------------------------

st.markdown("""
<style>

    /* ======== GLOBAL ======== */
    html, body, [class*="css"]  {
        background-color: #101010 !important;
        color: #FFFFFF !important;
        font-family: "Segoe UI", sans-serif;
    }

    /* ======== SIDEBAR ======== */
    section[data-testid="stSidebar"] {
        background-color: #0D0D0D !important;
        border-right: 2px solid #003D73 !important;
    }
    section[data-testid="stSidebar"] .css-1n76uvr {
        color: white !important;
    }

    /* ======== BOTÕES ======== */
    button[kind="primary"] {
        background-color: #003D73 !important;
        color: white !important;
        border-radius: 6px !important;
        border: 1px solid #0072BB !important;
    }

    button:hover {
        background-color: #0072BB !important;
        color: white !important;
    }

    /* ======== CHAT INPUT ======== */
    div[data-baseweb="textarea"] > textarea {
        background-color: #161616 !important;
        color: white !important;
        border-radius: 10px !important;
        border: 1px solid #003D73 !important;
        padding: 12px !important;
    }

    /* ======== USER MESSAGE BUBBLE ======== */
    .user_msg {
        background-color: #003D73 !important;
        padding: 14px;
        border-radius: 10px;
        color: white !important;
        margin-bottom: 8px;
        border: 1px solid #0072BB;
    }

    /* ======== ASSISTANT MESSAGE BUBBLE ======== */
    .assistant_msg {
        background-color: #161616 !important;
        padding: 14px;
        border-radius: 10px;
        color: #FFFFFF !important;
        border-left: 4px solid #00A652 !important;
        margin-bottom: 8px;
    }

    /* ======== THINKING BOX ======== */
    .thinking_box {
        background-color: #161616 !important;
        padding: 16px;
        border-radius: 10px;
        border-left: 4px solid #0072BB !important;
        color: white !important;
        margin-top: 10px;
        white-space: normal;
        word-wrap: break-word;
    }

</style>
""", unsafe_allow_html=True)

st.title("💁‍♂️ Pergunte ao Bentinho")
st.caption("Não esqueça de selecionar o agente que deseja a informação ao lado 👈")


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
        # st.sidebar.success("✅ Chave privada decodificada com sucesso.")

        # ---------------------------------------------------------
        # 2️⃣ Gera o fingerprint (SPKI DER → SHA256 Base64)
        # ---------------------------------------------------------
        self.public_fingerprint = self._calculate_public_key_fingerprint()
        # st.sidebar.write(f"**Fingerprint:** `{self.public_fingerprint}`")

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
        #st.sidebar.write("### 🧩 JWT Debug")
        #st.sidebar.write(f"**iss:** {payload['iss']}")
        #st.sidebar.write(f"**sub:** {payload['sub']}")
        #st.sidebar.text_area("🪪 Token JWT Gerado", token, height=150)

        self.token = token
        self.renew_time = now + self.renewal_delay
        #st.sidebar.success("✅ JWT gerado com sucesso.")
        return token

    # ---------------------------------------------------------
    def get_token(self):
        now = int(time.time())
        if now >= self.renew_time:
            #st.sidebar.warning("♻️ Renovando JWT...")
            self.generate_token()
        return self.token


# ---------------------------------------------------------
# STREAMING DE RESPOSTAS DO CORTEX (tipo "Thinking steps")
# ---------------------------------------------------------
def send_prompt_to_cortex(prompt, agent, jwt):
    url = f"https://{ACCOUNT}.snowflakecomputing.com/api/v2/databases/SNOWFLAKE_INTELLIGENCE/schemas/AGENTS/agents/{agent}:run"

    headers = {
        "Authorization": f"Bearer {jwt}",
        "Accept": "text/event-stream",
        "Content-Type": "application/json",
    }

    body = {
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": prompt}]
            }
        ]
    }

    response = requests.post(url, headers=headers, json=body, stream=True)

    # CAIXAS STREAMLIT
    thinking_box = st.empty()
    answer_box = st.empty()

    # BUFFERS
    thinking_buffer = ""
    answer_buffer = ""
    final_answer = None
    current_event = None

    # ---- Renderizador HTML Responsivo para o pensamento ----
    def render_thinking(text):
        safe_text = text.replace("\n", "<br>")
        thinking_box.markdown(
            f"""
            <div style="
                background-color:#111;
                padding:12px;
                border-radius:8px;
                line-height:1.45;
                font-size:15px;
                border-left: 4px solid #ff4081;
                word-wrap: break-word;
                white-space: normal;
            ">
                <div style="font-size:18px;margin-bottom:8px;">
                    🧠 <b>Pensando...</b>
                </div>
                {safe_text}
            </div>
            """,
            unsafe_allow_html=True
        )

    # ------------------ LOOP SSE ------------------
    for raw in response.iter_lines():
        if not raw:
            continue

        line = raw.decode("utf-8", errors="ignore").strip()

        # Identifica o tipo do evento
        if line.startswith("event:"):
            current_event = line.replace("event:", "").strip()
            continue

        # Dados do evento
        if not line.startswith("data:"):
            continue

        raw_json = line.replace("data:", "").strip()

        if raw_json == "[DONE]":
            break

        try:
            data = json.loads(raw_json)
        except:
            continue

        # ---------------- THINKING STREAM ----------------
        if current_event == "response.thinking.delta":
            delta = data.get("text", "")
            thinking_buffer += delta
            render_thinking(thinking_buffer)

        elif current_event == "response.thinking":
            txt = data.get("text", "")
            thinking_buffer = txt
            render_thinking(txt)

        # ---------------- ANSWER STREAM ----------------
        elif current_event == "response.text.delta":
            delta = data.get("text", "")
            answer_buffer += delta
            #answer_box.markdown(answer_buffer)

        # ---------------- FINAL BLOCK ----------------
        elif current_event == "response":
            for block in data.get("content", []):
                if block.get("type") == "text":
                    final_answer = block.get("text")

    # Remove o box de pensamento
    thinking_box.empty()

    # ---------------- RETORNO FINAL ----------------
    # 1) Se houve streaming da resposta → use-a
    if answer_buffer.strip():
        return answer_buffer.strip()

    # 2) Senão, use a resposta final consolidada
    if final_answer and final_answer.strip():
        return final_answer.strip()

    # 3) Último caso
    return "⚠️ Nenhum conteúdo retornado."



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
st.sidebar.header("⚙️ Selecione o agente")
selected_agent = st.sidebar.selectbox(
    "Selecione o agente de IA:",
    list(AGENTS.keys()),
    label_visibility="collapsed"  # Oculta o texto, mas mantém acessibilidade
)
agent_cfg = AGENTS[selected_agent]
agent_name = agent_cfg["agent"]
semantic_model = agent_cfg["semantic_model"]
st.sidebar.markdown("---")
#st.sidebar.write(f"**Usuário:** {USER}")
#st.sidebar.write(f"**Conta:** {ACCOUNT}")
#st.sidebar.write(f"**Renovação:** {time.strftime('%H:%M:%S', time.localtime(jwt_gen.renew_time))}")

# ---------------------------------------------------------
# HISTÓRICO DE CHAT
# ---------------------------------------------------------
if "messages" not in st.session_state:
    st.session_state.messages = []

for msg in st.session_state.messages:
    st.chat_message(msg["role"]).write(msg["content"])

# ---------------------------------------------------------
# INPUT DO USUÁRIO + STREAMING
# ---------------------------------------------------------
prompt = st.chat_input("Digite sua pergunta...")

if prompt:
    st.session_state.messages.append({"role": "user", "content": prompt})
    st.chat_message("user", avatar="🤔").markdown(f"<div class='user_msg'>{prompt}</div>", unsafe_allow_html=True)

    #with st.spinner(f"Agente de {selected_agent} pensando..."):
    #    resposta = send_prompt_to_cortex(prompt, agent_name, jwt_token)
    status_placeholder = st.empty()
    status_placeholder.markdown(f"🧠 Agente **{selected_agent}** pensando...")

    resposta = send_prompt_to_cortex(prompt, agent_name, jwt_token)

    status_placeholder.empty()


    st.chat_message("assistant", avatar="💁‍♂️").write(resposta)
    st.session_state.messages.append({"role": "assistant", "content": resposta,  "avatar": "💁‍♂️"})
    