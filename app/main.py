# main.py
import os
import asyncio
from dotenv import load_dotenv
import tornado.web

load_dotenv()

# Auth
from app.handlers.auth import RegisterHandler, LoginHandler
# Users
from app.handlers.users_list import UsersListHandler
from app.handlers.admin_users import AdminUserHandler


PORT = int(os.environ.get("PORT", 8000))
DEBUG = os.environ.get("DEBUG", "true").lower() == "true"

class HealthCheckHandler(tornado.web.RequestHandler):
    def get(self):
        self.write({"status": "ok", "message": "Service is running"})


def make_app():
    return tornado.web.Application(
        [
            # Health
            (r"/health", HealthCheckHandler),

            # Auth
            (r"/auth/register", RegisterHandler),
            (r"/auth/login", LoginHandler),

            # Users
            (r"/users", UsersListHandler),                              
            (r"/admin/users/([a-z0-9_]{3,30})", AdminUserHandler),       
        ],
        debug=DEBUG,
        xsrf_cookies=False
    )

async def main():
    app = make_app()
    app.listen(PORT)
    print(f"Tornado server running on http://localhost:{PORT} (debug={DEBUG})")
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
