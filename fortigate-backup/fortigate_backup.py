import os
import sys
import warnings
from datetime import datetime
from getpass import getpass

import requests
from colorama import Fore, Style

from get_secrets import get_secrets

RED = Fore.RED
NORMAL = Style.RESET_ALL


def backup(password: str):
    """Back up the Fortigate config to a file."""

    if password == "\0":
        endpoint = "/api/v2/monitor/system/config/backup/"
    else:
        endpoint = f"/api/v2/monitor/system/config/backup/?password={password}"

    secrets = get_secrets(
        url=os.getenv("VAULT_URL"),
        token=os.getenv("FORTINET_TOKEN"),
        path=os.getenv("FORTINET_PATH"),
    )

    host = secrets["data"]["fw_host"]
    token = secrets["data"]["fw_token"]
    params = {"scope": "global"}
    headers = {"Authorization": f"Bearer {token}"}
    fw_url = f"{host}{endpoint}"
    date_string = "%Y%m%d_%H%M%S"
    timestamp = datetime.now().strftime(date_string)
    hostname = host.split(":")[1].lstrip("//")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")

        try:
            r = requests.get(fw_url, headers=headers, params=params, verify=False)

            with open(f"{hostname}_{timestamp}.conf", "w") as f:
                for line in r.text.split("\n"):
                    print(line, file=f)

        except Exception as e:
            print(e, "Something went wrong.  Is the url correct?  Exiting...")
            sys.exit(1)


def main():
    print("\n" + "#" * 30)
    print("#  FORTIGATE BACKUP UTILITY  #")
    print("#" * 30 + "\n")
    print("The backup file format will be <hostname>_<timestamp>.conf")

    choice = input("Use a password to encrypt the backup? (Y|N): ")

    match choice.lower():
        case "y":
            pwd1 = getpass("Enter a password (minimum 8 characters): ")
            if len(pwd1) <= 8:
                print("Password is too short. Exiting...")
                sys.exit(1)
            else:
                pwd2 = getpass("Retype the password: ")

            if pwd1 == pwd2:
                bkup_passwd = pwd1
                print("Password has been set.  Keep it in a safe place.")
                print("It will be needed to restore from this backup file.")
            else:
                print("Passwords do not match.  Exiting...")
                sys.exit(1)
        case "n":
            bkup_passwd = "\0"
            print("The backup file will not be encrypted.")
        case _:
            print(f"{RED}==> Invalid input.  Exiting...{NORMAL}")
            sys.exit(1)

    backup(bkup_passwd)


if __name__ == "__main__":
    main()
