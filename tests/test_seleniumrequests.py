import os
import json
import sys

import pytest
import requests
import http.server
import http.cookies

from selenium import webdriver
from seleniumrequests import Firefox, Chrome, Remote
from seleniumrequests.request import run_http_server
from selenium.webdriver.chrome.service import Service as ChromeService

from smart_webdriver_manager import ChromeDriverManager

import logging
logger = logging.getLogger(__name__)


WEBDRIVER_CLASSES = Chrome, Firefox


@pytest.fixture(scope='function')
def dummy_server(request):
    class DummyRequestHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write("<html></html>".encode("utf-8"))
        def log_message(self, format, *args):
            pass
    dummy_server = run_http_server(DummyRequestHandler)
    return dummy_server


@pytest.fixture(scope='function')
def echo_header_server(request):
    class EchoHeaderRequestHandler(http.server.BaseHTTPRequestHandler):
        """Server returns header with echo=data
        """
        def do_GET(self):
            data = json.dumps(dict(self.headers))
            self.send_response(200)
            self.send_header("echo", data)
            self.end_headers()
            self.wfile.write("<html></html>".encode("utf-8"))
        def log_message(self, format, *args):
            http.server.BaseHTTPRequestHandler.log_message(self, format, *args)
    echo_header_server = run_http_server(EchoHeaderRequestHandler)
    return echo_header_server


@pytest.fixture(scope='function')
def set_cookie_server(request):
    class SetCookieRequestHandler(http.server.BaseHTTPRequestHandler):
        """Server returns some=cookie cookie in the response
        """
        def do_GET(self):
            self.send_response(200)
            if "set-cookie" in self.headers:
                self.send_header("set-cookie", "some=cookie")
            self.end_headers()
            self.wfile.write("<html></html>".encode("utf-8"))
        def log_message(self, format, *args):
            pass
    set_cookie_server = run_http_server(SetCookieRequestHandler)
    return set_cookie_server


def instantiate_webdriver(webdriver_class):
    logger.info(f"Instanting {webdriver_class}")
    try:
        if webdriver_class == Chrome:
            cdm = ChromeDriverManager(100)
            options = webdriver.ChromeOptions()
            options.binary_location = cdm.get_browser()
            options.add_argument('--headless')
            options.add_argument(f'--user-data-dir={cdm.get_browser_user_data()}')
            service = ChromeService(executable_path=executable_path)
            return webdriver_class(service=service, chrome_options=options)
        if webdriver_class == Firefox:
            options = webdriver.FirefoxOptions()
            options.add_argument('--headless')
            return webdriver_class(options=options)
    except Exception as exc:
        pytest.skip("WebDriver not available")


def make_window_handling_test(webdriver_class):

    def test_window_handling(dummy_server):
        """Test that on making a request we remain on original window handle
        """
        logger.info(f"Running 'make_window_handling_test' for {webdriver_class}")
        webdriver = instantiate_webdriver(webdriver_class)

        webdriver.get(dummy_server)
        original_window_handle = webdriver.current_window_handle
        webdriver.execute_script(f"window.open('{dummy_server}', '_blank');")
        logger.info(f"Opened blank window {dummy_server}")

        original_window_handles = set(webdriver.window_handles)
        webdriver.request("GET", "https://www.google.com/")

        assert webdriver.current_window_handle == original_window_handle
        assert set(webdriver.window_handles) == original_window_handles # no additional windows opened

        webdriver.quit()
        logger.info(f"Quit webdriver")

    return test_window_handling


def make_headers_test(webdriver_class):

    def test_headers(echo_header_server):
        logger.info(f"Running 'make_headers_test' for {webdriver_class}")

        webdriver = instantiate_webdriver(webdriver_class)
        # TODO: Add more cookie examples with additional fields, such as
        # expires, path, comment, max-age, secure, version, httponly
        cookies = (
            {"domain": "127.0.0.1", "name": "hello", "value": "world"},
            {"domain": "127.0.0.1", "name": "another", "value": "cookie"},
        )
        webdriver.get(echo_header_server) # open page prior to setting cookies
        for cookie in cookies:
            logger.info(f"Added {cookie}")
            webdriver.add_cookie(cookie)
        logger.info(f"Requesting {echo_header_server} with extra cookies")
        response = webdriver.request("GET", echo_header_server, headers={"extra": "header"}, cookies={"extra": "cookie"})
        logger.info(f"Got response")
        sent_headers = requests.structures.CaseInsensitiveDict(json.loads(response.headers["echo"]))

        # Simply assert that the User-Agent isn't requests' default one, which
        # means that it and the rest of the headers must have been overwritten
        assert sent_headers["user-agent"] != requests.utils.default_user_agent()
        # Check if the additional header was sent as well
        assert "extra" in sent_headers and sent_headers["extra"] == "header"
        cookies = http.cookies.SimpleCookie()
        # Python 2's Cookie module expects a string object, not Unicode
        cookies.load(sent_headers["cookie"])
        assert "hello" in cookies and cookies["hello"].value == "world"
        assert "another" in cookies and cookies["another"].value == "cookie"
        # Check if the additional cookie was sent as well
        assert "extra" in cookies and cookies["extra"].value == "cookie"

        webdriver.quit()

    return test_headers


def make_cookie_test(webdriver_class):

    def test_cookies(set_cookie_server):
        logger.info(f"Running 'make_cookie_test' for {webdriver_class}")

        webdriver = instantiate_webdriver(webdriver_class)
        # Make sure that the WebDriver itself doesn't receive the Set-Cookie
        # header, instead the requests request should receive it and set it
        # manually within the WebDriver instance.
        webdriver.request("GET", set_cookie_server, headers={"set-cookie": ""})
        # Open the URL so that we can actually get the cookies
        webdriver.get(set_cookie_server)

        cookie = webdriver.get_cookies()[0]
        assert cookie["name"] == "some" and cookie["value"] == "cookie"
        # TODO: Improve this
        # Ensure that the Requests session cookies were cleared and only
        # cookies directly taken from the WebDriver instance are used
        assert not webdriver.requests_session.cookies

        webdriver.quit()

    return test_cookies


for webdriver_class in WEBDRIVER_CLASSES:
    name = webdriver_class.__name__.lower()
    globals()[f"test_{name}_window_handling"] = make_window_handling_test(webdriver_class)
    globals()[f"test_{name}_set_cookie"] = make_cookie_test(webdriver_class)
    globals()[f"test_{name}_headers"] = make_headers_test(webdriver_class)
