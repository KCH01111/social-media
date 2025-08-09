# main.py

import os
from dotenv import load_dotenv

# Load .env file BEFORE importing anything that uses environment variables
load_dotenv()

import tornado.ioloop
import tornado.web
from auth.handlers import RegisterHandler, LoginHandler
from users.handlers import UserDetailHandler, MeHandler, UsersListHandler, UserSearchHandler, UserStatsHandler, AdminUserHandler

PORT = int(os.environ.get("PORT", 8000))
DEBUG = os.environ.get("DEBUG", "true").lower() == "true"

class HealthCheckHandler(tornado.web.RequestHandler):
    def get(self):
        self.write({"status": "ok", "message": "Service is running"})

def make_app():
    return tornado.web.Application([
        (r"/health", HealthCheckHandler),
        (r"/auth/register", RegisterHandler),
        (r"/auth/login", LoginHandler),
        (r"/users",UsersListHandler),
        (r"/users/me",MeHandler),
        (r"/users/search",UserSearchHandler),
        (r"/users/([a-z0-9_]{3,30})/stats",UserStatsHandler),
        (r"/users/([a-z0-9_]{3,30})",UserDetailHandler),
        (r"/admin/users/([a-z0-9_]{3,30})", AdminUserHandler),
    ], debug=DEBUG)

if __name__ == "__main__":
    app = make_app()
    app.listen(PORT)
    print(f"Tornado server running on http://localhost:{PORT} (debug={DEBUG})")
    tornado.ioloop.IOLoop.current().start()
