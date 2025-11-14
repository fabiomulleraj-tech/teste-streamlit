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
# CONFIGURAÇÕES BÁSICAS
# ---------------------------------------------------------
st.set_page_config(page_title="Bentinho", page_icon="❄️", layout="wide")

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
                "content": [
                    {"type": "text", "text": prompt}
                ]
            }
        ]
    }

    response = requests.post(url, headers=headers, json=body, stream=True)

    thinking_box = st.empty()
    answer_box = st.empty()

    thinking_buffer = ""
    answer_buffer = ""
    final_answer = None

    for raw in response.iter_lines():
        if not raw:
            continue

        line = raw.decode("utf-8", errors="ignore").strip()

        # 1) Capturar "event:"
        if line.startswith("event:"):
            current_event = line.replace("event:", "").strip()
            continue

        # 2) Capturar "data:"
        if line.startswith("data:"):
            raw_json = line.replace("data:", "").strip()
            if raw_json == "[DONE]":
                break

            try:
                data = json.loads(raw_json)
            except:
                continue
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

            # THINKING STREAM (token a token)
            if current_event == "response.thinking.delta":
                delta = data.get("text", "")
                thinking_buffer += delta
                render_thinking(thinking_buffer)

            # THINKING FINAL
            elif current_event == "response.thinking":
                txt = data.get("text", "")
                thinking_buffer = txt
                render_thinking(txt)

            # RESPOSTA STREAM (token a token)
            elif current_event == "response.text.delta":
                delta = data.get("text", "")
                answer_buffer += delta
                answer_box.markdown(answer_buffer)

            # RESPOSTA FINAL consolidada
            elif current_event == "response":
                for block in data.get("content", []):
                    if block.get("type") == "text":
                        final_answer = block.get("text")

            continue

    thinking_box.empty()

    if answer_buffer:
        return answer_buffer.strip()

    if final_answer:
        return final_answer.strip()

    return "⚠ Nenhum conteúdo retornado."


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
    st.chat_message("user", avatar="🤔").write(prompt)

    #with st.spinner(f"Agente de {selected_agent} pensando..."):
    #    resposta = send_prompt_to_cortex(prompt, agent_name, jwt_token)
    status_placeholder = st.empty()
    status_placeholder.markdown(f"🧠 Agente de **{selected_agent}** pensando...")

    resposta = send_prompt_to_cortex(prompt, agent_name, jwt_token)

    status_placeholder.empty()


    st.chat_message("assistant", avatar="💁‍♂️").write(resposta)
    st.session_state.messages.append({"role": "assistant", "content": resposta})