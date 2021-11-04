"""Wrapper for Selenium (modified version of seleniumrequests)

The module spawns a simple HTTP server to copy and later emulate the
request headers that are sent by the browser controlled by the WebDriver. This
is done so that manual HTTP requests can be made with another library that look
similar or identical to those that would have been sent by the browser. Since this
process simply needs to open a new window and navigate to the localhost URL for
less than a second, the window can be immediately closed again. This immediate
closing is handled by JavaScript in the HTML of the opened page, which simply
calls window.close() as soon as the page has loaded.
"""
import threading
import warnings
import http.server
import urllib.parse
import time
import json

import requests
import tldextract

from selenium.common.exceptions import NoSuchWindowException, WebDriverException
from selenium.webdriver.common.utils import free_port

import logging
logger = logging.getLogger(__name__)


FIND_WINDOW_HANDLE_WARNING = (
    "Created window handle could not be found reliably. Using less reliable "
    "alternative method. JavaScript redirects are not supported and an "
    "additional GET request might be made for the requested URL."
)

HEADERS = None
UPDATER_HEADERS_MUTEX = threading.Semaphore()
UPDATER_HEADERS_MUTEX.acquire()


class SeleniumRequestsException(Exception):
    pass


class _HTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """Using a global value to pass around the headers dictionary reference seems
    to be the easiest way to get access to it, since the HTTPServer doesn't keep
    an object of the instance of the HTTPRequestHandler
    """
    def do_GET(self):
        global HEADERS
        HEADERS = requests.structures.CaseInsensitiveDict(self.headers)
        UPDATER_HEADERS_MUTEX.release()

        self.send_response(200)
        self.end_headers()
        self.wfile.write('<script type="text/javascript">window.close();</script>'.encode("utf-8"))

    def log_message(self, format, *args):
        """Log an arbitrary message and prepend the given thread name."""
        logger.debug("[ {} ] {} - [{}] {}".format(
            threading.current_thread().name,
            self.address_string(),
            self.log_date_time_string(),
            format%args))


def run_http_server(request_handler_class):
    """
    >>> address = run_http_server(_HTTPRequestHandler)
    >>> print("Address:", address) # doctest:+ELLIPSIS
    Address: http://127.0.0.1:...
    >>> print("Getting URL:", address) # doctest:+ELLIPSIS
    Getting URL: http://127.0.0.1:...
    >>> with requests.get(address) as f:
    ...     print("Code:", f.status_code)
    Code: 200
    """
    while True: # loop until bind port
        port = free_port()
        try:
            httpd = http.server.HTTPServer(("", port), request_handler_class)
            break
        except OSError:
            pass
    def serve_forever(httpd):
        with httpd:
            httpd.serve_forever()
    httpd.timeout = 10
    thread = threading.Thread(target=serve_forever, args=(httpd,))
    thread.daemon = True
    thread.start()
    logger.info(f"started HTTP sever on port {port}")
    return f"http://127.0.0.1:{port:d}"


def get_webdriver_request_headers(webdriver):

    address = run_http_server(_HTTPRequestHandler)
    original_window_handle = webdriver.current_window_handle
    current_handles = webdriver.window_handles

    def get_headers():
        """Timing issue with HTTPRequestHander loading on the thread;
        open two windows to capture headers
        """
        load = f"""
            window.open('{address}', '_blank');
            window.open('{address}', '_blank');
        """
        webdriver.execute_script(load)
        time.sleep(0.5)
        new_handles = webdriver.window_handles
        for handle in new_handles:
            if handle not in current_handles:
                webdriver.switch_to.window(handle)
                webdriver.close()

    global HEADERS
    while not HEADERS:
        try:
            get_headers()
        except NoSuchWindowException:
            logger.error("Unable to acquire webdriver resources for scrape. Exiting.")
            raise SeleniumRequestsException()

    UPDATER_HEADERS_MUTEX.acquire()
    webdriver.switch_to.window(original_window_handle) # NOT optional
    headers = HEADERS
    HEADERS = None

    # Remove the host header, which will simply contain the localhost address of the HTTPRequestHandler instance
    del headers["host"]
    return headers


def prepare_requests_cookies(webdriver_cookies):
    return {str(cookie["name"]): str(cookie["value"]) for cookie in webdriver_cookies}


def get_tld(url):
    """Top level domain getter, handle unknown domains

    >>> get_tld('http://127.0.0.1:9222/')
    '127.0.0.1'
    >>> get_tld('http://domain.onion/')
    'domain.onion'
    >>> get_tld('http://www.google.com/')
    'google.com'
    >>> get_tld('http://www.forum.bbc.co.uk/')
    'bbc.co.uk'
    """
    components = tldextract.extract(url)
    # Since the registered domain could not be extracted, assume that it's simply an IP and strip away the protocol
    # prefix and potentially trailing rest after "/" away. If it isn't, this fails gracefully for unknown domains, e.g.:
    # "http://domain.onion/" -> "domain.onion". If it doesn't look like a valid address at all, return the URL
    # unchanged.
    if not components.registered_domain:
        try:
            return url.split("://", 1)[1].split(":", 1)[0].split("/", 1)[0]
        except IndexError:
            return url

    return components.registered_domain


def find_window_handle(webdriver, predicate):
    """Looking for previously used window handle if one exists. Start with
    current active handle and work backwards.
    """
    original_window_handle = webdriver.current_window_handle
    if predicate(webdriver):
        return original_window_handle

    # Start search beginning with the most recently added window handle: the chance is higher that this is the correct
    # one in most cases
    for window_handle in reversed(webdriver.window_handles):
        if window_handle == original_window_handle:
            continue

        # This exception can occur if the window handle was closed between accessing the window handles and attempting
        # to switch to it, in which case it can be silently ignored.
        try:
            webdriver.switch_to.window(window_handle)
        except NoSuchWindowException: # handle closed during iteration
            continue

        if predicate(webdriver):
            return window_handle

    # Simply switch back to the original window handle and return None if no matching window handle was found
    webdriver.switch_to.window(original_window_handle)


def make_match_domain_predicate(domain):
    def predicate(webdriver):
        try:
            return get_tld(webdriver.current_url) == domain
        # This exception can occur if the current window handle was closed
        except NoSuchWindowException: # in case handle becomes closed
            pass

    return predicate


class RequestsSessionMixin:

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.requests_session = requests.Session()
        self.__has_webdriver_request_headers = False

    def add_cookie(self, cookie_dict):
        try:
            super().add_cookie(cookie_dict)
        except WebDriverException as exception:
            details = json.loads(exception.msg)
            if details['errorMessage'] == 'Unable to set Cookie':
                raise

    def request(self, method, url, **kwargs):
        if not self.__has_webdriver_request_headers:
            # Workaround for Chrome bug: https://bugs.chromium.org/p/chromedriver/issues/detail?id=1077
            if self.name == "chrome":
                window_handles_before = len(self.window_handles)
                self.requests_session.headers = get_webdriver_request_headers(self)

                # Wait until the newly opened window handle is closed again, to prevent switching to it just as it is
                # about to be closed
                while len(self.window_handles) > window_handles_before:
                    time.sleep(0.01)
            else:
                self.requests_session.headers = get_webdriver_request_headers(self)

            self.__has_webdriver_request_headers = True

            # Delete cookies from the request headers, to prevent overwriting manually set cookies later. This should
            # only happen when the webdriver has cookies set for the localhost
            if "cookie" in self.requests_session.headers:
                del self.requests_session.headers["cookie"]

        original_window_handle = None
        opened_window_handle = None
        requested_tld = get_tld(url)
        if not get_tld(self.current_url) == requested_tld:
            original_window_handle = self.current_window_handle

            # Try to find an existing window handle that matches the requested top-level domain
            predicate = make_match_domain_predicate(requested_tld)
            window_handle = find_window_handle(self, predicate)

            # Create a new window handle manually in case it wasn't found
            if not window_handle:
                previous_window_handles = set(self.window_handles)
                components = urllib.parse.urlsplit(url)
                self.execute_script(f"window.open('{components.scheme}://{components.netloc}/', '_blank');")
                difference = set(self.window_handles) - previous_window_handles

                if len(difference) == 1:
                    opened_window_handle = difference.pop()
                    self.switch_to.window(opened_window_handle)
                else:
                    logger.warning(FIND_WINDOW_HANDLE_WARNING)
                    opened_window_handle = find_window_handle(self, predicate)

                    # Window handle could not be found during first pass. There might have been a redirect and the top-
                    # level domain changed
                    if not opened_window_handle:
                        response = self.requests_session.get(url, stream=True)
                        current_tld = get_tld(response.url)
                        if current_tld != requested_tld:
                            predicate = make_match_domain_predicate(current_tld)
                            opened_window_handle = find_window_handle(self, predicate)
                            if not opened_window_handle:
                                raise SeleniumRequestsException("window handle could not be found")

        # Acquire WebDriver's cookies and merge them with potentially passed cookies
        cookies = prepare_requests_cookies(self.get_cookies())
        if "cookies" in kwargs:
            cookies.update(kwargs["cookies"])
        kwargs["cookies"] = cookies

        response = self.requests_session.request(method, url, **kwargs)

        # Set cookies received from the HTTP response in the WebDriver
        current_tld = get_tld(self.current_url)
        for cookie in response.cookies:
            # Setting domain to None automatically instructs most webdrivers to use the domain of the current window
            # handle
            cookie_dict = {"domain": cookie.domain, "name": cookie.name, "value": cookie.value, "secure": cookie.secure}
            if cookie.expires:
                cookie_dict["expiry"] = cookie.expires
            if cookie.path_specified:
                cookie_dict["path"] = cookie.path

            self.add_cookie(cookie_dict)

        # Don't keep cookies in the Requests session, only use the WebDriver's
        self.requests_session.cookies.clear()
        if opened_window_handle:
            self.close()
        if original_window_handle:
            self.switch_to.window(original_window_handle)

        return response


# backwards-compatibility
RequestMixin = RequestsSessionMixin


if __name__ == '__main__':
    import doctest
    doctest.testmod()
