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
# CONFIGURAÇÕES BÁSICAS
# ---------------------------------------------------------
st.set_page_config(page_title="Bentinho", page_icon="❄️", layout="wide")

st.title("🤖 Fale com o Bentinho")

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
def send_prompt_to_cortex(prompt, agent, jwt_token, debug=False):
    url = f"https://{ACCOUNT}.snowflakecomputing.com/api/v2/databases/SNOWFLAKE_INTELLIGENCE/schemas/AGENTS/agents/{agent}:run"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
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

    # 🔍 Mostra detalhes de requisição no modo debug
    if debug:
        with st.expander("🧩 DEBUG REQUEST", expanded=False):
            st.write("**URL:**", url)
            st.json(headers)
            st.json(body)
            st.code(jwt_token, language="bash")

    try:
        with requests.post(url, headers=headers, json=body, stream=True, timeout=180) as resp:
            if resp.status_code != 200:
                if debug:
                    with st.expander("❌ DEBUG RESPONSE", expanded=True):
                        st.write("**Status:**", resp.status_code)
                        st.text(resp.text)
                return f"⚠️ Erro HTTP {resp.status_code}: {resp.text}"

            full_text = ""
            thinking_box = st.empty()
            chat_box = st.empty()

            # ✅ percorre o stream manualmente e decodifica bytes -> texto
            for raw_line in resp.iter_lines():
                if not raw_line:
                    continue
                try:
                    line = raw_line.decode("utf-8").strip()
                    if line.startswith("data: "):
                        data = json.loads(line[len("data: "):])

                        # mostra raciocínio
                        if "thinking" in data:
                            thinking_box.markdown(
                                f"🧠 **Pensando...**\n\n```\n{data['thinking']}\n```"
                            )

                        # mostra tokens de saída
                        if "output" in data:
                            full_text += data["output"].get("text", "")
                            chat_box.markdown(full_text)

                        # 🔍 exibe eventos SSE no modo debug
                        if debug:
                            with st.expander("📡 DEBUG SSE EVENT", expanded=False):
                                st.json(data)

                except Exception as e:
                    if debug:
                        st.sidebar.warning(f"⚠️ Falha ao processar chunk SSE: {e}")

            thinking_box.empty()

            if debug:
                with st.expander("✅ DEBUG FINAL OUTPUT", expanded=True):
                    st.write(full_text)

            return full_text.strip() or "⚠️ Nenhum conteúdo retornado."

    except Exception as e:
        if debug:
            st.sidebar.error(f"❌ Erro no streaming SSE: {e}")
        return f"❌ Erro ao consultar o agente: {e}"

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
    st.chat_message("user").write(prompt)

    with st.spinner(f"Consultando agente {selected_agent}..."):
        resposta = send_prompt_to_cortex(prompt, agent_name, jwt_token, debug=True)

    st.chat_message("assistant").write(resposta)
    st.session_state.messages.append({"role": "assistant", "content": resposta})
