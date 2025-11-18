import streamlit as st
import ssl
import hashlib
import os
import time
from ldap3 import Server, Connection, SIMPLE, Tls

# ---------------------------------------------------------
# CONFIGURAÇÃO DO AD
# ---------------------------------------------------------
AD_SERVERS = [
    "ldaps://SRVADPRD.central.local:636",
    "ldaps://SRVADPRD2.central.local:636"
]
AD_DOMAIN = "CENTRAL"

# ---------------------------------------------------------
# CONFIGURAÇÃO DO TOKEN
# ---------------------------------------------------------
COOKIE_NAME = "aj_auth_token"
COOKIE_DAYS = 90
TOKEN_EXP = COOKIE_DAYS * 86400
TOKEN_RENEW_THRESHOLD = 5 * 86400  # renova se tiver mais de 5 dias

# Banco de tokens
if "auth_tokens" not in st.session_state:
    st.session_state.auth_tokens = {}


# ---------------------------------------------------------
# AUTENTICAÇÃO AD
# ---------------------------------------------------------
def authenticate_ad(username, password):
    user_dn = f"{AD_DOMAIN}\\{username}"

    tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)

    last_error = None
    for srv in AD_SERVERS:
        try:
            server = Server(srv, use_ssl=True, tls=tls)

            conn = Connection(
                server,
                user=user_dn,
                password=password,
                authentication=SIMPLE,
                auto_bind=True
            )
            conn.unbind()
            return True

        except Exception as e:
            last_error = str(e)
            continue

    st.error(f"Erro AD: {last_error}")
    return False


# ---------------------------------------------------------
# IDENTIFICADOR DO NAVEGADOR
# ---------------------------------------------------------
def get_browser_id():
    ua = st.context.headers.get("User-Agent", "")
    ip = st.context.headers.get("X-Forwarded-For", st.context.client.ip)
    raw = f"{ua}-{ip}"
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------
# CRIAR TOKEN
# ---------------------------------------------------------
def create_token(username, browser_id):
    raw = f"{username}-{browser_id}-{os.urandom(32)}-{time.time()}"
    token = hashlib.sha256(raw.encode()).hexdigest()

    st.session_state.auth_tokens[token] = {
        "username": username,
        "browser": browser_id,
        "created": time.time(),
        "expires": time.time() + TOKEN_EXP
    }

    st.cookies.set(
        COOKIE_NAME,
        token,
        max_age=TOKEN_EXP,
        secure=True,
        samesite="Strict"
    )

    return token


# ---------------------------------------------------------
# RENOVAÇÃO DO TOKEN
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
# LOGIN AUTOMÁTICO
# ---------------------------------------------------------
def auto_login():
    token = st.cookies.get(COOKIE_NAME)
    if not token:
        return False

    data = st.session_state.auth_tokens.get(token)
    if not data:
        return False

    # validação do navegador
    browser_id = get_browser_id()
    if data["browser"] != browser_id:
        return False

    # expiração
    if data["expires"] < time.time():
        return False

    # renova token
    new_token = renew_token_if_needed(token, browser_id)
    if new_token != token:
        st.cookies.set(COOKIE_NAME, new_token, max_age=TOKEN_EXP)

    st.session_state.logged_in = True
    st.session_state.user = data["username"]
    return True


# ---------------------------------------------------------
# LOGOUT
# ---------------------------------------------------------
def logout():
    token = st.cookies.get(COOKIE_NAME)

    if token and token in st.session_state.auth_tokens:
        del st.session_state.auth_tokens[token]

    st.cookies.delete(COOKIE_NAME)
    st.session_state.clear()
    st.rerun()


# ---------------------------------------------------------
# LOGIN FLOW
# ---------------------------------------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

# 1 - tentativa de login automático
if not st.session_state.logged_in:
    if auto_login():
        st.success(f"🔓 Login automático como {st.session_state.user}")
        st.rerun()

# 2 - login manual
if not st.session_state.logged_in:
    st.title("🔐 Login (Active Directory)")

    username = st.text_input("Usuário (sem domínio)")
    password = st.text_input("Senha", type="password")

    if st.button("Entrar", use_container_width=True):
        if authenticate_ad(username, password):
            st.session_state.logged_in = True
            st.session_state.user = username

            browser_id = get_browser_id()
            create_token(username, browser_id)

            st.success("Login OK!")
            st.rerun()
        else:
            st.error("Usuário ou senha inválidos")

    st.stop()

# ---------------------------------------------------------
# ÁREA LOGADA
# ---------------------------------------------------------
st.sidebar.success(f"👤 Usuário autenticado: {st.session_state.user}")
st.sidebar.button("🚪 Sair", on_click=logout)

st.title("Bem-vindo, " + st.session_state.user)
st.write("Sessão com persistência de 90 dias habilitada.")
