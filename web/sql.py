import contextlib
import requests
from bs4 import BeautifulSoup, ResultSet
from urllib.parse import urljoin

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " \
                          "Chrome/83.0.4103.106 Safari/537.36 "


def get_all_forms(url: str) -> ResultSet:
    """Given an url, it returns all forms from the HTML content"""
    return BeautifulSoup(s.get(url).content, "html.parser").find_all("form")


def get_form_details(form) -> dict:
    """
    This function extracts all possible useful information about an HTML form
    """
    # get the form action (target url)
    try:
        action = form.attrs.get("action").lower()
    except Exception as e:
        print(e)
        action = None
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    return {"action": action, "method": method, "inputs": inputs}


def is_vulnerable(response: requests.Response) -> bool:
    """A simple boolean function that determines whether a page
    is SQL Injection vulnerable to its response"""
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    return any(error in response.content.decode().lower() for error in errors)


def scan_sql_injection(url: str) -> bool:
    # test on URL
    for c in "\"'":
        # add quote/double quote character to the URL
        new_url = f"{url}{c}"
        # make the HTTP request
        res = s.get(new_url)
        if is_vulnerable(res):
            # SQL Injection detected on the URL itself,
            # no need to proceed for extracting forms and submitting them
            return True
    # test on HTML forms
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            # the data body we want to submit
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["value"] or input_tag["type"] == "hidden":
                    # any input form that has some value or hidden,
                    # just use it in the form body
                    with contextlib.suppress(Exception):
                        data[input_tag["name"]] = input_tag["value"] + c
                elif input_tag["type"] != "submit":
                    # all others except submit, use some junk data with special character
                    data[input_tag["name"]] = f"test{c}"
            # join the url with the action (form request URL)
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)
            # test whether the resulting page is vulnerable
            if is_vulnerable(res):
                return True
    return False


if __name__ == "__main__":
    victim = "http://testphp.vulnweb.com/artists.php?artist=1"
    print(scan_sql_injection(victim))
