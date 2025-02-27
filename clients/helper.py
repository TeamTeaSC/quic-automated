def is_client_tcp(client: str) -> bool:
    """ Given client name, returns true iff client uses TCP/HTTP2. """
    return ("h2" in client)