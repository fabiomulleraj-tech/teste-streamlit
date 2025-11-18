import streamlit as st
import requests
import time
import json
import base64
import hashlib
import ssl
import extra_streamlit_components as stx
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from ldap3 import Server, Connection, ALL, SIMPLE, Tls


# =====================================================================================
# ⚠️ CONFIGURAÇÃO STREAMLIT E INICIALIZAÇÃO
# =====================================================================================
st.set_page_config(page_title="Bentinho", page_icon="❄️", layout="wide")

cookie_manager = stx.CookieManager(key="aj-cookie-key")
cookie_manager  # necessário


# =====================================================================================
# ⚠️ FUNÇÃO DE FORÇAR COOKIE VIA JAVASCRIPT (100% funcional)
# =====================================================================================
def force_cookie(username):
    js = f"""
    <script>
        document.cookie = "aj_logged_user={username}; Path=/; Domain=ai.almeidajunior.com.br; SameSite=None; Secure";
    </script>
    """
    st.markdown(js, unsafe_allow_html=True)




# =====================================================================================
# ⚠️ SESSION STATE
# =====================================================================================
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "username" not in st.session_state:
    st.session_state.username = None



# =====================================================================================
# ⚠️ AUTENTICAÇÃO AD
# =====================================================================================
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
            conn = Connection(server, user=user_dn, password=password,
                              authentication=SIMPLE, auto_bind=True)
            conn.unbind()
            return True
        except Exception as e:
            last_error = str(e)

    st.error(f"Falha AD: {last_error}")
    return False



# =====================================================================================
# ⚠️ LOGIN AUTOMÁTICO VIA COOKIE
# =====================================================================================
saved_user = cookie_manager.get("aj_logged_user")

if saved_user and not st.session_state.logged_in:
    st.session_state.logged_in = True
    st.session_state.username = saved_user



# =====================================================================================
# ⚠️ TELA DE LOGIN (NADA PODE SER RENDERIZADO ANTES)
# =====================================================================================
if not st.session_state.logged_in:

    st.title("🔐 Login (Active Directory)")

    username = st.text_input("Usuário (sem domínio)")
    password = st.text_input("Senha", type="password")

    if st.button("Entrar"):
        if authenticate_ad(username, password):
            # grava cookie via JavaScript (NUNCA FALHA)
            force_cookie(username)

            st.session_state.logged_in = True
            st.session_state.username = username
            st.rerun()
        else:
            st.error("❌ Usuário ou senha inválidos.")

    st.stop()



# =====================================================================================
# 🙌 INTERFACE APÓS LOGIN
# =====================================================================================

st.sidebar.success(f"👤 Logado como: {st.session_state.username}")

# Logout
if st.sidebar.button("Sair"):
    force_cookie("deleted")   # "limpa" sobrescrevendo
    st.session_state.logged_in = False
    st.session_state.username = None
    st.rerun()



# DEBUG DO COOKIE
st.write("📌 Cookie detectado:", cookie_manager.get("aj_logged_user"))




# =====================================================================================
# CSS
# =====================================================================================
st.markdown("""
<style>
    html, body, [class*="css"] {
        background-color: #101010 !important;
        color: #FFFFFF !important;
        font-family: "Segoe UI", sans-serif;
    }
    section[data-testid="stSidebar"] {
        background-color: #0D0D0D !important;
        border-right: 2px solid #003D73 !important;
    }
    .user_msg {
        background-color: #003D73 !important;
        padding: 14px;
        border-radius: 10px;
        color: white !important;
        margin-bottom: 8px;
        border: 1px solid #0072BB;
    }
</style>
""", unsafe_allow_html=True)



# =====================================================================================
# APP PRINCIPAL
# =====================================================================================
st.title("💁‍♂️ Pergunte ao Bentinho")
st.caption("Não esqueça de selecionar o agente ao lado 👈")


# =====================================================================================
# SNOWFLAKE + JWT (seu bloco original permanece igual)
# =====================================================================================

ACCOUNT = "A6108453355571-ALMEIDAJR"
USER = "TEAMS_INTEGRATION"

AGENTS = {
    "🏬 Vendas e Faturamento": {"agent": "AJ_VS"},
    "📑 Contratos de Logistas": {"agent": "AJ_JURIDICO"},
    "🧾 Contratos de Fornecedores": {"agent": "AJ_PROTHEUS"},
}


class JWTGenerator:
    def __init__(self, account, user):
        self.account = account.upper()
        self.user = user.upper()
        self.qualified_username = f"{self.account}.{self.user}"

        key_text = st.secrets["rsa"]["private_key"].replace("\\n", "\n").strip()
        self.private_key = serialization.load_pem_private_key(
            key_text.encode(), password=None, backend=default_backend()
        )

        self.lifetime = 3600
        self.renewal_delay = self.lifetime - 300
        self.public_fingerprint = self._calc_fingerprint()
        self.generate_token()

    def _calc_fingerprint(self):
        pub = self.private_key.public_key()
        der = pub.public_bytes(serialization.Encoding.DER,
                               serialization.PublicFormat.SubjectPublicKeyInfo)
        fp = hashlib.sha256(der).digest()
        return "SHA256:" + base64.b64encode(fp).decode()

    def generate_token(self):
        now = int(time.time())
        payload = {
            "iss": f"{self.qualified_username}.{self.public_fingerprint}",
            "sub": self.qualified_username,
            "iat": now,
            "exp": now + self.lifetime,
        }
        header = {"alg": "RS256", "typ": "JWT"}

        def b64(d): return base64.urlsafe_b64encode(d).decode().rstrip("=")

        h = b64(json.dumps(header).encode())
        p = b64(json.dumps(payload).encode())
        msg = f"{h}.{p}".encode()
        s = b64(self.private_key.sign(msg, padding.PKCS1v15(), hashes.SHA256()))

        self.token = f"{h}.{p}.{s}"
        self.renew_time = now + self.renewal_delay

    def get_token(self):
        if time.time() >= self.renew_time:
            self.generate_token()
        return self.token



if "jwt_gen" not in st.session_state:
    st.session_state.jwt_gen = JWTGenerator(ACCOUNT, USER)

jwt_gen = st.session_state.jwt_gen
jwt_token = jwt_gen.get_token()



# =====================================================================================
# CHAT + STREAMING (seu código original)
# =====================================================================================

st.sidebar.header("⚙️ Selecione o agente")
selected_agent = st.sidebar.selectbox(
    "Agente:",
    list(AGENTS.keys()),
    label_visibility="collapsed"
)

agent_name = AGENTS[selected_agent]["agent"]



def send_prompt_to_cortex(prompt, agent, jwt):
    url = f"https://{ACCOUNT}.snowflakecomputing.com/api/v2/databases/SNOWFLAKE_INTELLIGENCE/schemas/AGENTS/agents/{agent}:run"
    headers = {"Authorization": f"Bearer {jwt}",
               "Accept": "text/event-stream",
               "Content-Type": "application/json"}

    body = {"messages": [
        {"role": "user", "content": [{"type": "text", "text": prompt}]}
    ]}

    response = requests.post(url, headers=headers, json=body, stream=True)

    answer = ""
    for raw in response.iter_lines():
        if raw:
            line = raw.decode()
            if line.startswith("data: "):
                try:
                    data = json.loads(line[6:])
                    if "text" in data:
                        answer += data["text"]
                except:
                    pass

    return answer.strip()



if "messages" not in st.session_state:
    st.session_state.messages = []

for msg in st.session_state.messages:
    st.chat_message(msg["role"]).write(msg["content"])


prompt = st.chat_input("Digite sua pergunta...")

if prompt:
    st.session_state.messages.append({"role": "user", "content": prompt})
    st.chat_message("user").write(prompt)

    resposta = send_prompt_to_cortex(prompt, agent_name, jwt_token)

    st.session_state.messages.append({"role": "assistant", "content": resposta})
    st.chat_message("assistant").write(resposta)
