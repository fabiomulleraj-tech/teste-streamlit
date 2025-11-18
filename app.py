import streamlit as st
import datetime
from ldap3 import Server, Connection, ALL, SUBTREE, Tls
import ssl

# =====================================
# CONFIGURAÇÕES DO AD
# =====================================
AD_SERVER = "10.60.10.253"
AD_DOMAIN = "CENTRAL.local"
AD_SEARCH_BASE = "DC=CENTRAL,DC=local"
SESSION_DURATION_HOURS = 24
# =====================================


# =====================================
# VERIFICA VALIDADE DA SESSÃO
# =====================================
def check_session_valid():
    if "logged_in" not in st.session_state:
        return False

    if not st.session_state["logged_in"]:
        return False

    expiry = st.session_state.get("session_expiry")

    if not expiry:
        return False

    if datetime.datetime.now() > expiry:
        st.session_state.clear()
        return False

    return True


# =====================================
# BUSCA DN DO USUARIO NO AD
# =====================================
def get_user_dn(username):
    tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)

    server = Server(
        AD_SERVER,
        port=636,
        use_ssl=True,
        tls=tls_config,
        get_info=ALL
    )

    # Bind anônimo / bind de leitura (funciona na maioria dos ADs)
    conn = Connection(server, authentication=None, auto_bind=True)

    conn.search(
        search_base=AD_SEARCH_BASE,
        search_filter=f"(sAMAccountName={username})",
        search_scope=SUBTREE,
        attributes=["distinguishedName"]
    )

    if len(conn.entries) == 0:
        return None

    dn = conn.entries[0].distinguishedName.value
    conn.unbind()
    return dn


# =====================================
# AUTENTICAÇÃO VIA SIMPLE BIND + LDAPS
# =====================================
def authenticate(username, password):
    user_dn = get_user_dn(username)

    if not user_dn:
        return False

    tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)

    try:
        server = Server(
            AD_SERVER,
            port=636,
            use_ssl=True,
            tls=tls_config,
            get_info=ALL
        )

        # SIMPLE BIND com DN + senha
        conn = Connection(
            server,
            user=user_dn,
            password=password,
            authentication="SIMPLE",
            auto_bind=True
        )

        conn.unbind()
        return True

    except Exception as e:
        st.error(f"Erro de autenticação: {e}")
        return False


# =====================================
# UI ÁREA RESTRITA
# =====================================
def main_app():
    st.title("💁‍♂️ Bentinho — Área Restrita")
    st.success(f"Usuário autenticado: {st.session_state['username']}")

    st.write("Conteúdo do sistema...")

    if st.button("Sair"):
        st.session_state.clear()
        st.rerun()


# =====================================
# UI LOGIN
# =====================================
def login_screen():
    st.title("🔐 Login AD")

    username = st.text_input("Usuário (sAMAccountName)")
    password = st.text_input("Senha", type="password")

    if st.button("Entrar", use_container_width=True):
        if authenticate(username, password):
            st.session_state["logged_in"] = True
            st.session_state["username"] = username
            st.session_state["session_expiry"] = (
                datetime.datetime.now() +
                datetime.timedelta(hours=SESSION_DURATION_HOURS)
            )
            st.rerun()
        else:
            st.error("Usuário ou senha inválidos.")


# =====================================
# CONTROLE DE FLUXO
# =====================================
st.set_page_config(page_title="Login AD", layout="centered")

if check_session_valid():
    main_app()
else:
    login_screen()

