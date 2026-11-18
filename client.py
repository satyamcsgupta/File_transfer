
from html.parser import HTMLParser
from getpass import getpass
import requests
import sys

SERVER = "http://127.0.0.1:5000"


class CSRFTokenParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.token = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "input" and attributes.get("name") == "csrf_token":
            self.token = attributes.get("value")
        elif tag == "meta" and attributes.get("name") == "csrf-token":
            self.token = attributes.get("content")


def upload_file(filepath):
    try:
        with open(filepath, "rb") as file:
            with requests.Session() as client:
                login_page = client.get(SERVER + "/", timeout=30)
                login_page.raise_for_status()
                login_token = CSRFTokenParser()
                login_token.feed(login_page.text)
                if not login_token.token:
                    print("Login failed: could not read the security token.")
                    return

                password = getpass("Vault password: ")
                login_response = client.post(
                    SERVER + "/",
                    data={
                        "password": password,
                        "csrf_token": login_token.token
                    },
                    timeout=30
                )

                if login_response.status_code != 200:
                    print("Login failed. Check the vault password.")
                    return

                dashboard_token = CSRFTokenParser()
                dashboard_token.feed(login_response.text)
                if not dashboard_token.token:
                    print("Upload failed: could not read the security token.")
                    return

                response = client.post(
                    SERVER + "/upload",
                    files={"file": file},
                    headers={"X-CSRF-Token": dashboard_token.token},
                    timeout=30
                )

                if response.status_code == 200:
                    data = response.json()
                    print("\nUpload Successful!")
                    print("File Name:", data["filename"])
                    print("Your File ID:", data["file_id"])
                else:
                    print("Upload Failed:", response.text)

    except FileNotFoundError:
        print("Error: File not found!")

    except requests.RequestException as e:
        print("Connection Error:", e)


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python client.py <file_path>")

    else:
        upload_file(sys.argv[1])
