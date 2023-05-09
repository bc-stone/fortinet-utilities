import csv
import os
import sys
import warnings

import requests

from get_secrets import get_secrets


def get_ip_objects(filename: str):
    """Retrieve a list of all the IP address objects on a Fortigate firewall"""

    secrets = get_secrets(
        url=os.getenv("VAULT_URL"),
        token=os.getenv("FORTINET_TOKEN"),
        path=os.getenv("FORTINET_PATH"),
    )

    host = secrets["data"]["fw_host"]
    endpoint = "/api/v2/cmdb/firewall/address/?access_token="
    token = secrets["data"]["fw_token"]
    content_filter = ""
    headers = ["NAME", "SUBNET", "START-IP", "END-IP", "FQDN", "TYPE"]

    url = (
        f"{host}{endpoint}{token}{content_filter}"
        if content_filter
        else f"{host}{endpoint}{token}"
    )

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")

        try:
            r = requests.get(url, verify=False).json()
            with open(filename, "w") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                for i in range(len(r["results"])):
                    r["results"][i].setdefault("subnet", "")
                    r["results"][i].setdefault("start-ip", "")
                    r["results"][i].setdefault("end-ip", "")
                    r["results"][i].setdefault("fqdn", "")
                    data = [
                        r["results"][i]["name"],
                        r["results"][i]["subnet"],
                        r["results"][i]["start-ip"],
                        r["results"][i]["end-ip"],
                        r["results"][i]["fqdn"],
                        r["results"][i]["type"],
                    ]

                    writer.writerow(data)
        except Exception as e:
            print(f"{repr(e)}\nSomething went wrong.  Is the url correct?  Exiting...")
            sys.exit()


def main():
    output_file = input("Enter a name for the csv output file: ")

    get_ip_objects(output_file)


if __name__ == "__main__":
    main()
