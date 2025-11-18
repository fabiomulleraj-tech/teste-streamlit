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
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from ldap3 import Server, Connection, ALL, SIMPLE, Tls
# ---------------------------------------------------------
# CONFIGURAÇÃO DO AD
# ---------------------------------------------------------
AD_SERVERS = [
    "ldaps://SRVADPRD.central.local:636",
    "ldaps://SRVADPRD2.central.local:636"
]

def authenticate_ad(username, password):
    user_dn = f"CENTRAL\\{username}"

    # TLS sem validação forte (evita erro de certificado self-signed)
    tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)

    for srv in AD_SERVERS:
        try:
            server = Server(srv, use_ssl=True, get_info=ALL, tls=tls)

            conn = Connection(
                server,
                user=user_dn,
                password=password,
                authentication=SIMPLE,   # ← NÃO USA NTLM
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
# TELA DE LOGIN
# ---------------------------------------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    st.title("🔐 Login (Active Directory)")
    username = st.text_input("Usuário (apenas nome, sem domínio)")
    password = st.text_input("Senha", type="password")

    if st.button("Entrar"):
        if authenticate_ad(username, password):
            st.session_state.logged_in = True
            st.session_state.user = username
            st.success("✅ Autenticado com sucesso!")
            st.rerun()
        else:
            st.error("❌ Usuário ou senha inválidos.")

    st.stop()



st.sidebar.success(f"👤 Usuário: {st.session_state.user}")