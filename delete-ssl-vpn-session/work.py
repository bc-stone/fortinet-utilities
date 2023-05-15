import json
import os
import sys
import warnings
from datetime import datetime

import requests
from rich.console import Console
from rich.table import Table

from get_secrets import get_secrets

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


def get_ssl_vpn():
    """Get a list of active ssl vpn tunnels"""

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")

        try:
            r = requests.get(url, verify=False).json()
        except Exception as e:
            print(e, "Something went wrong.  Is the url correct?  Exiting...")
            sys.exit()

    return r["results"]


def render_table():
    current_time = datetime.now()

    table = Table(
        title=f"\nCURRENTLY CONNECTED SSL VPN TUNNELS as of {current_time}",
        title_justify="left",
    )
    table.show_lines = True
    headers = [
        "INDEX",
        "USERNAME",
        "LOGIN TIME",
        "TUNNEL ADDRESS",
        "REMOTE ADDRESS",
        "BYTES IN",
        "BYTES OUT",
    ]
    for header in headers:
        table.add_column(header=header, justify="left")

    for i in results:
        table.add_row(
            str(i["subsessions"][0]["index"]),
            i["user_name"],
            i["last_login_time"],
            i["subsessions"][0]["aip"],
            i["remote_host"],
            str(i["subsessions"][0]["in_bytes"]),
            str(i["subsessions"][0]["out_bytes"]),
        )

    console = Console()
    console.print(table)


def delete_session():
    del_endpoint = "/api/v2/monitor/vpn/ssl/delete?access_token="
    url = f"{host}{del_endpoint}{token}"
    session = input("\nEnter the index of the session to delete: ")

    for i in results:
        if session in str(i["subsessions"][0]["index"]):
            headers = {
                "accept": "application/json",
                "Content-Type": "application/json",
            }
            data = {"type": "subsession", "index": int(session)}

            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                try:
                    requests.post(
                        url=url,
                        data=json.dumps(data),
                        headers=headers,
                        verify=False,
                    )
                    print(f"Session {session} deleted.")
                    sys.exit(0)
                except Exception as e:
                    print(e)
    else:
        print(f"Session {session} not found.")
        sys.exit(1)


def main():
    global results
    results = get_ssl_vpn()
    render_table()
    delete_session()


if __name__ == "__main__":
    main()
