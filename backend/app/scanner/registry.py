"""Registry mapping module keys to detection module classes."""
from app.scanner.modules.http_headers import HTTPHeaderModule
from app.scanner.modules.sqli import SQLInjectionModule
from app.scanner.modules.xss import XSSModule
from app.utils.modules import MODULE_HTTP_HEADERS, MODULE_SQLI, MODULE_XSS

MODULE_CLASSES = {
    MODULE_SQLI: SQLInjectionModule,
    MODULE_XSS: XSSModule,
    MODULE_HTTP_HEADERS: HTTPHeaderModule,
}


def get_module_class(key):
    return MODULE_CLASSES.get(key)
