import csv
import os
import warnings

import requests

from get_secrets import get_secrets


def list_botnet_ip(filename: str):
    """List all IP-based botnet entries in the FortiGuard botnet database.

    Args:
        file (str): Name of the csv output file.
    """
    secrets = get_secrets(
        url=os.getenv("VAULT_URL"),
        token=os.getenv("FORTINET_TOKEN"),
        path=os.getenv("FORTINET_PATH"),
    )

    host = secrets["data"]["fw_host"]
    endpoint = "/api/v2/monitor/system/botnet/?access_token="
    token = secrets["data"]["fw_token"]
    url = f"{host}{endpoint}{token}"

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        r = requests.get(url, verify=False).json()

    with open(filename, "w") as f:
        fieldnames = ["ip", "protocol", "port", "hit_count", "bot_name"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(r["results"])


def main():
    output_file = input("Enter a name for the csv output file: ")

    list_botnet_ip(output_file)


if __name__ == "__main__":
    main()
