import hvac


def get_secrets(url, token, path):
    """Retreive secrets from Hashicorp Vault

    Args:
        url (str): URL of the Vault server.
        token (str): Vault token (preferably read-only) for the desired secrets.
        path (str): Unique name of the secrets contained in the Secrets Engine.

    Returns:
        dict: The retrieved secrets in `key: value` format.
    """
    client = hvac.Client(url=url, token=token)

    return client.secrets.kv.v1.read_secret(mount_point="kv", path=path)
