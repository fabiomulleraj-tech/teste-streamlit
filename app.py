import streamlit as st
import ssl
import hashlib
import os
import time
import json
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
TOKEN_EXP_SECONDS = COOKIE_DAYS * 86400
TOKEN_RENEW_THRESHOLD = 86400 * 5   # renova o token a cada 5 dias

# “Banco de tokens” em memória (para produção use Redis)
if "auth_tokens" not in st.session_state:
    st.session_state.auth_tokens = {}  # token: data structure


# ---------------------------------------------------------
# AUTENTICAÇÃO NO AD
# ---------------------------------------------------------
def authenticate_ad(username, password):
    user_dn = f"{AD_DOMAIN}\\{username}"

    tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
    last_error = None

    for srv in AD_SERVERS:
        try:
            server = Server(srv, use_ssl=True, get_info=None, tls=tls)

            conn = Connection(
                server,
                user=user_dn,
                password=password,
                authentication=SIMPLE,   # SIMPLE + DOMAIN\user → funciona no seu AD
                auto_bind=True
            )

            conn.unbind()
            return True

        except Exception as e:
            last_error = str(e)
            continue

    st.error(f"Falha AD: {last_error}")
    return False


# ---------------------------------------------------------
# CRIAR TOKEN PERSISTENTE DE 90 DIAS
# ---------------------------------------------------------
def create_token(username, browser_id):
    raw = f"{username}-{browser_id}-{os.urandom(32)}-{time.time()}"
    token = hashlib.sha256(raw.encode()).hexdigest()

    st.session_state.auth_tokens[token] = {
        "username": username,
        "browser_id": browser_id,
        "created": time.time(),
        "expires": time.time() + TOKEN_EXP_SECONDS
    }

    st.experimental_set_cookie(
        COOKIE_NAME,
        token,
        max_age=TOKEN_EXP_SECONDS,
        secure=True,
        samesite="Strict"
    )

    return token


# ---------------------------------------------------------
# RENOVAR TOKEN (sliding expiration)
# ---------------------------------------------------------
def renew_token_if_needed(token, browser_id):
    data = st.session_state.auth_tokens.get(token)
    if not data:
        return token

    age = time.time() - data["created"]
    if age < TOKEN_RENEW_THRESHOLD:
        return token  # ainda não precisa renovar

    username = data["username"]
    new_token = create_token(username, browser_id)
    del st.session_state.auth_tokens[token]
    return new_token


# ---------------------------------------------------------
# LOGIN AUTOMÁTICO PELO COOKIE
# ---------------------------------------------------------
def auto_login():
    token = st.experimental_get_cookie(COOKIE_NAME)
    if not token:
        return False

    data = st.session_state.auth_tokens.get(token)
    if not data:
        return False

    # verificação por navegador (User-Agent)
    browser_id = get_browser_identifier()
    if data["browser_id"] != browser_id:
        return False  # impedindo roubo de cookie

    if data["expires"] < time.time():
        return False  # expirado

    # renova token se necessário
    new_token = renew_token_if_needed(token, browser_id)
    if new_token != token:
        st.experimental_set_cookie(COOKIE_NAME, new_token, max_age=TOKEN_EXP_SECONDS)

    st.session_state.logged_in = True
    st.session_state.user = data["username"]
    return True


# ---------------------------------------------------------
# IDENTIFICADOR DO NAVEGADOR
# ---------------------------------------------------------
def get_browser_identifier():
    ua = st.context.headers.get("User-Agent", "")
    ip = st.context.headers.get("X-Forwarded-For", st.context.client.ip)
    raw = f"{ua}-{ip}"
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------
# LOGOUT
# ---------------------------------------------------------
def logout():
    token = st.experimental_get_cookie(COOKIE_NAME)
    if token and token in st.session_state.auth_tokens:
        del st.session_state.auth_tokens[token]

    st.experimental_set_cookie(COOKIE_NAME, "", max_age=0)
    st.session_state.clear()
    st.rerun()


# ---------------------------------------------------------
# INICIALIZAÇÃO DO LOGIN
# ---------------------------------------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

# Tentativa de login automática
if not st.session_state.logged_in:
    if auto_login():
        st.success(f"🔓 Login automático como {st.session_state.user}")
        st.rerun()

# Se ainda não estiver logado → tela de login
if not st.session_state.logged_in:
    st.title("🔐 Login Active Directory")

    username = st.text_input("Usuário (sem domínio)")
    password = st.text_input("Senha", type="password")

    if st.button("Entrar", use_container_width=True):
        if authenticate_ad(username, password):
            st.session_state.logged_in = True
            st.session_state.user = username

            browser_id = get_browser_identifier()
            create_token(username, browser_id)

            st.success("✅ Logado com sucesso!")
            st.rerun()
        else:
            st.error("❌ Usuário ou senha inválidos.")

    st.stop()


# ---------------------------------------------------------
# ÁREA LOGADA
# ---------------------------------------------------------
st.sidebar.success(f"👤 Usuário: {st.session_state.user}")
st.sidebar.button("🚪 Sair", on_click=logout)

st.title("Bem-vindo ao sistema Bentinho!")
st.write("Sessão autenticada com persistência de 90 dias.")
