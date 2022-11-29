__version__ = '1.3.3'

from selenium.webdriver import Chrome as _Chrome
from selenium.webdriver import Firefox as _Firefox
from selenium.webdriver import Remote as _Remote

from seleniumrequests.request import RequestsSessionMixin


class Firefox(RequestsSessionMixin, _Firefox):
    pass


class Chrome(RequestsSessionMixin, _Chrome):
    pass


class Remote(RequestsSessionMixin, _Remote):
    pass
