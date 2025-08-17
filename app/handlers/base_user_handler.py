from handlers.base_handler import BaseHandler

class BaseUserHandler(BaseHandler):
    def set_default_headers(self):
        super().set_default_headers()
        self.set_header(
            "Access-Control-Allow-Methods",
            "GET, POST, PATCH, DELETE, OPTIONS"
        )
