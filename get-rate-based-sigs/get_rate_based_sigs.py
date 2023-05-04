import csv
import os
import sys
import warnings

import requests

from get_secrets import get_secrets


def get_rate_based_sigs(filename: str):
    """Returns a csv file of rate-based signatures in the IPS package.

    Args:
        filename (str): Name of the csv output file.
    """

    secrets = get_secrets(
        url=os.getenv("VAULT_URL"),
        token=os.getenv("FORTINET_TOKEN"),
        path=os.getenv("FORTINET_PATH"),
    )

    host = secrets["data"]["fw_host"]
    endpoint = "/api/v2/monitor/ips/rate-based/select/?access_token="
    token = secrets["data"]["fw_token"]
    url = f"{host}{endpoint}{token}"
    content_filter = ""

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

    with open(filename, "w") as f:
        fieldnames = [
            "name",
            "id",
            "rate-count",
            "rate-duration",
            "rate-track",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(r["results"])


def main():
    output_file = input("Enter a name for the csv output file: ")

    get_rate_based_sigs(output_file)


if __name__ == "__main__":
    main()
