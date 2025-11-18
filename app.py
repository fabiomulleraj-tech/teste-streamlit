import streamlit as st
import datetime
from ldap3 import Server, Connection, ALL, SUBTREE, Tls
import ssl

# =====================================
# CONFIG AD
# =====================================
AD_SERVERS = ["10.60.10.253", "10.60.10.251"]   # dois Domain Controllers
AD_DOMAIN = "central.local"
AD_SEARCH_BASE = "DC=central,DC=local"
SESSION_DURATION_HOURS = 24
# =====================================


def check_session_valid():
    if "logged_in" not in st.session_state:
        return False
    if not st.session_state["logged_in"]:
        return False
    expiry = st.session_state.get("session_expiry")
    if not expiry or datetime.datetime.now() > expiry:
        st.session_state.clear()
        return False
    return True


# ============= BUSCA DN =============
def get_user_dn(username):
    tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)

    for dc in AD_SERVERS:
        try:
            server = Server(dc, port=636, use_ssl=True, tls=tls_config)
            conn = Connection(server, auto_bind=True)

            conn.search(
                search_base=AD_SEARCH_BASE,
                search_filter=f"(sAMAccountName={username})",
                search_scope=SUBTREE,
                attributes=["distinguishedName", "userPrincipalName"]
            )

            if conn.entries:
                entry = conn.entries[0]
                dn = entry.distinguishedName.value
                upn = entry.userPrincipalName.value
                conn.unbind()
                return dn, upn

        except:
            pass

    return None, None


# ============= AUTENTICAÇÃO =============
def authenticate(username, password):
    st.warning("🔍 DEBUG: Iniciando busca no AD…")

    user_dn, user_upn = get_user_dn(username)

    st.write(f"DN encontrado: {user_dn}")
    st.write(f"UPN encontrado: {user_upn}")

    if not user_upn:
        st.error("⚠ Usuário não encontrado no AD.")
        return False

    tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)

    for dc in AD_SERVERS:
        st.info(f"Tentando autenticar no DC: {dc}")

        try:
            server = Server(dc, port=636, use_ssl=True, tls=tls_config)

            conn = Connection(
                server,
                user=user_upn,
                password=password,
                authentication="SIMPLE",
                auto_bind=True
            )

            st.success(f"Autenticado com sucesso no DC {dc}")
            conn.unbind()
            return True

        except Exception as e:
            st.error(f"Erro no DC {dc}: {e}")

    st.error("❌ TODOS os DCs recusaram a autenticação.")
    return False


# ============= UI PRINCIPAL =============
def main_app():
    st.title("💁‍♂️ Bentinho — Área Restrita")
    st.success(f"Autenticado como: {st.session_state['username']}")
    st.write("Conteúdo protegido…")

    if st.button("Sair"):
        st.session_state.clear()
        st.rerun()


# ============= LOGIN UI =============
def login_screen():
    st.title("🔐 Login AD")

    username = st.text_input("Usuário (ex: rafael.stange)")
    password = st.text_input("Senha", type="password")

    if st.button("Entrar", use_container_width=True):
        if authenticate(username, password):
            st.session_state["logged_in"] = True
            st.session_state["username"] = username
            st.session_state["session_expiry"] = datetime.datetime.now() + datetime.timedelta(hours=SESSION_DURATION_HOURS)
            st.rerun()
        else:
            st.error("Usuário ou senha incorretos ou AD não respondeu.")


# ============= FLUXO =============
st.set_page_config(page_title="Login AD", layout="centered")

if check_session_valid():
    main_app()
else:
    login_screen()
