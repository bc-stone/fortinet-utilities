import os
import sys
import warnings
from datetime import datetime

import requests
from rich.console import Console
from rich.table import Table

from get_secrets import get_secrets


def get_routes():
    """
    Retrieve a list of all active routing table entries - uses IPv4  by default but can be easily changed by editing the `endpoint` variable below.
    """

    # Change ipv4 to ipv6 here to get active ipv6 routes
    endpoint = "/api/v2/monitor/router/ipv4/select/?access_token="

    secrets = get_secrets(
        url=os.getenv("VAULT_URL"),
        token=os.getenv("FORTINET_TOKEN"),
        path=os.getenv("FORTINET_PATH"),
    )

    host = secrets["data"]["fw_host"]
    token = secrets["data"]["fw_token"]

    content_filter = ""

    current_time = datetime.now()
    current_time = current_time.strftime("%Y-%m-%d  %H:%M:%S")

    table = Table(title=f"\nFortigate Active Routes as of {current_time}")
    table.show_lines = True
    table.add_column("Route", justify="left")
    table.add_column("Gateway", justify="left")
    table.add_column("Interface", justify="left")
    table.add_column("Type", justify="left")

    url = (
        f"{host}{endpoint}{token}{content_filter}"
        if content_filter
        else f"{host}{endpoint}{token}"
    )
    
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")

        try:
            r = requests.get(url, verify=False).json()
        except Exception:
            print("Something went wrong.  Is the url correct?  Exiting...")
            sys.exit()


        for i in (r["results"]):
            table.add_row(i["ip_mask"], i["gateway"], i["interface"], i["type"])
   
        console = Console()
        console.print(table)


if __name__ == '__main__':
    get_routes()
