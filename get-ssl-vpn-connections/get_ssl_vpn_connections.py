import os
import sys
import warnings
from datetime import datetime

import requests
from rich.console import Console
from rich.table import Table

from get_secrets import get_secrets


def get_ssl_vpn():
    """Get a list of active ssl vpn tunnels"""

    secrets = get_secrets(
        url=os.getenv("VAULT_URL"),
        token=os.getenv("FORTINET_TOKEN"),
        path=os.getenv("FORTINET_PATH"),
    )

    host = secrets["data"]["fw_host"]
    token = secrets["data"]["fw_token"]
    endpoint = "/api/v2/monitor/vpn/ssl/select/?access_token="

    content_filter = ""

    url = (
        f"{host}{endpoint}{token}{content_filter}"
        if content_filter
        else f"{host}{endpoint}{token}"
    )

    current_time = datetime.now()

    table = Table(
        title=f"\nCURRENTLY CONNECTED SSL VPN TUNNELS as of {current_time}",
        title_justify="left",
    )
    table.show_lines = True
    headers = [
        "USERNAME",
        "LOGIN TIME",
        "TUNNEL ADDRESS",
        "REMOTE ADDRESS",
        "BYTES IN",
        "BYTES OUT",
    ]
    for header in headers:
        table.add_column(header=header, justify="left")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")

        try:
            r = requests.get(url, verify=False).json()

            for i in r["results"]:
                table.add_row(
                    i["user_name"],
                    i["last_login_time"],
                    i["subsessions"][0]["aip"],
                    i["remote_host"],
                    str(i["subsessions"][0]["in_bytes"]),
                    str(i["subsessions"][0]["out_bytes"]),
                )

        except Exception as e:
            print(e, "Something went wrong.  Is the url correct?  Exiting...")
            sys.exit()

    console = Console()
    console.print(table)


if __name__ == "__main__":
    get_ssl_vpn()
