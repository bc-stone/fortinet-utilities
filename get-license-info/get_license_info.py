import os
import sys
import warnings
from datetime import datetime

import requests
from colorama import Fore, Style

from get_secrets import get_secrets

YELLOW = Fore.YELLOW
NORMAL = Style.RESET_ALL


def get_license_info():
    """Retrieve comprehensive licensing info from a Fortigate"""

    secrets = get_secrets(
        url=os.getenv("VAULT_URL"),
        token=os.getenv("FORTINET_TOKEN"),
        path=os.getenv("FORTINET_PATH"),
    )

    host = secrets["data"]["fw_host"]
    endpoint = "/api/v2/monitor/license/status/select/?access_token="
    token = secrets["data"]["fw_token"]
    content_filter = ""
    tstamp_list = [
        "expires",
        "next_scheduled_update",
        "last_update",
        "last_update_attempt",
    ]

    url = (
        f"{host}{endpoint}{token}{content_filter}"
        if content_filter
        else f"{host}{endpoint}{token}"
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")

        try:
            r = requests.get(url, verify=False).json()
        except Exception as e:
            print(
                f"{repr(e)}\nSomething went wrong.  Is the url correct?  Exiting..."
            )
            sys.exit()

        for i in r["results"]:
            print(f"\n{YELLOW}{i.upper()}{NORMAL}:")
            for k, v in r["results"][i].items():
                if k in tstamp_list:
                    v = datetime.fromtimestamp(v)
                if isinstance(v, dict):
                    pad = " " * 4
                    print(f"{pad}{k.upper()}:")
                    for c, d in v.items():
                        if c in tstamp_list:
                            d = datetime.fromtimestamp(d)
                        pad = " " * 6
                        if isinstance(d, dict):
                            print(f"{pad}{c.upper()}:")
                            for e, f in dict(d).items():
                                if e in tstamp_list:
                                    f = datetime.fromtimestamp(f)
                                pad = " " * 8
                                print(f"{pad}{e.upper()} : {str(f)}")
                        else:
                            print(f"{pad}{c.upper()} : {str(d)}")
                else:
                    pad = " " * 2
                    print(f"{pad}{k.upper()} : {str(v)}")


def main():
    print(f"\n{YELLOW}LICENSE INFO AS OF {datetime.now()}{NORMAL}")

    get_license_info()


if __name__ == "__main__":
    main()
