def authenticate_ad(username, password):
    # Formato aceito pelo seu AD via SIMPLE+LDAPS
    user_with_domain = f"CENTRAL\\{username}"

    # Ignorar validação do certificado (self-signed/CA interna)
    tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)

    last_error = "Erro desconhecido"

    for srv in AD_SERVERS:
        try:
            server = Server(srv, use_ssl=True, get_info=ALL, tls=tls)

            conn = Connection(
                server,
                user=user_with_domain,
                password=password,
                authentication=SIMPLE,
                auto_bind=True
            )

            conn.unbind()
            return True

        except Exception as e:
            last_error = str(e)
            continue

    st.error(f"Falha ao autenticar no AD: {last_error}")
    return False
