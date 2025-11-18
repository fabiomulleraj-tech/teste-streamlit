import streamlit as st
import ssl
import hashlib
import os
import time
from ldap3 import Server, Connection, SIMPLE, Tls
from streamlit_js_eval import streamlit_js_eval

# ---------------------------------------------------------
# CONFIG AD
# ---------------------------------------------------------
AD_SERVERS = [
    "ldaps://SRVADPRD.central.local:636",
    "ldaps://SRVADPRD2.central.local:636"
]
AD_DOMAIN = "CENTRAL"

# ---------------------------------------------------------
# TOKEN CONFIG
# ---------------------------------------------------------
TOKEN_KEY = "aj_auth_token"
TOKEN_DAYS = 90
TOKEN_EXP_SECONDS = TOKEN_DAYS * 86400
TOKEN_RENEW_THRESHOLD = 5 * 86400  # renova token a cada 5 dias

if "auth_tokens" not in st.session_state:
    st.session_state.auth_tokens = {}

# ---------------------------------------------------------
# AD LOGIN
# ---------------------------------------------------------
def authenticate_ad(username, password):
    user_dn = f"{AD_DOMAIN}\\{username}"
    tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
    last_error = None

    for srv in AD_SERVERS:
        try:
            server = Server(srv, use_ssl=True, tls=tls)
            conn = Connection(server, user=user_dn, password=password, authentication=SIMPLE, auto_bind=True)
            conn.unbind()
            return True

        except Exception as e:
            last_error = str(e)
            continue

    st.error(f"Erro AD: {last_error}")
    return False

# ---------------------------------------------------------
# BROWSER FINGERPRINT
# ---------------------------------------------------------
def get_browser_id():
    ua = st.context.headers.get("User-Agent", "")
    ip = st.context.client.ip
    raw = f"{ua}-{ip}"
    return hashlib.sha256(raw.encode()).hexdigest()

# ---------------------------------------------------------
# TOKEN FUNCTIONS (LOCALSTORAGE)
# ---------------------------------------------------------
def ls_get(key):
    return streamlit_js_eval(f"localStorage.getItem('{key}')", as_string=True)

def ls_set(key, value):
    streamlit_js_eval(f"localStorage.setItem('{key}', '{value}')")

def ls_remove(key):
    streamlit_js_eval(f"localStorage.removeItem('{key}')")

# ---------------------------------------------------------
# CREATE TOKEN
# ---------------------------------------------------------
def create_token(username, browser_id):
    raw = f"{username}-{browser_id}-{os.urandom(32)}-{time.time()}"
    token = hashlib.sha256(raw.encode()).hexdigest()

    st.session_state.auth_tokens[token] = {
        "username": username,
        "browser": browser_id,
        "created": time.time(),
        "expires": time.time() + TOKEN_EXP_SECONDS
    }

    ls_set(TOKEN_KEY, token)
    return token

# ---------------------------------------------------------
# RENEW TOKEN
# ---------------------------------------------------------
def renew_token_if_needed(token, browser_id):
    data = st.session_state.auth_tokens.get(token)
    if not data:
        return token

    age = time.time() - data["created"]
    if age < TOKEN_RENEW_THRESHOLD:
        return token

    username = data["username"]
    new_token = create_token(username, browser_id)
    del st.session_state.auth_tokens[token]
    return new_token

# ---------------------------------------------------------
# AUTO LOGIN
# ---------------------------------------------------------
def auto_login():
    token = ls_get(TOKEN_KEY)
    if not token:
        return False

    data = st.session_state.auth_tokens.get(token)
    if not data:
        return False

    if data["expires"] < time.time():
        return False

    browser_id = get_browser_id()
    if data["browser"] != browser_id:
        return False

    # renovar
    new_token = renew_token_if_needed(token, browser_id)
    if new_token != token:
        ls_set(TOKEN_KEY, new_token)

    st.session_state.logged_in = True
    st.session_state.user = data["username"]
    return True

# ---------------------------------------------------------
# LOGOUT
# ---------------------------------------------------------
def logout():
    token = ls_get(TOKEN_KEY)

    if token and token in st.session_state.auth_tokens:
        del st.session_state.auth_tokens[token]

    ls_remove(TOKEN_KEY)
    st.session_state.clear()
    st.rerun()

# ---------------------------------------------------------
# LOGIN FLOW
# ---------------------------------------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

# auto login
if not st.session_state.logged_in:
    if auto_login():
        st.success(f"🔓 Login automático: {st.session_state.user}")
        st.rerun()

# manual login
if not st.session_state.logged_in:
    st.title("🔐 Login AD")

    username = st.text_input("Usuário (sem domínio)")
    password = st.text_input("Senha", type="password")

    if st.button("Entrar", use_container_width=True):
        if authenticate_ad(username, password):
            st.session_state.logged_in = True
            st.session_state.user = username
            browser_id = get_browser_id()
            create_token(username, browser_id)
            st.success("Login efetuado!")
            st.rerun()
        else:
            st.error("Usuário ou senha incorretos.")

    st.stop()

# ---------------------------------------------------------
# ÁREA LOGADA
# ---------------------------------------------------------
st.sidebar.success(f"👤 {st.session_state.user}")
st.sidebar.button("🚪 Sair", on_click=logout)

st.title(f"Bem-vindo, {st.session_state.user}!")
st.write("Sessão persistente de 90 dias com localStorage.")
