# main.py
import os
import asyncio
from dotenv import load_dotenv

load_dotenv()

import tornado.web

# Auth
from app.handlers.auth import RegisterHandler, LoginHandler
# Users
from app.handlers.users import (
    UsersListHandler,
    MeHandler,
    UserSearchHandler,
    UserStatsHandler,
    UserDetailHandler,
    AdminUserHandler,
)
# Posts
from app.handlers.posts import (
    PostsListHandler,
    PostsSearchHandler,
    PostDetailHandler,
    UpdatePostHandler,
    DeletePostHandler,
    CreatePostHandler,
)

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
            (r"/users", UsersListHandler),                               # GET list
            (r"/users/me", MeHandler),                                   # GET/PATCH/DELETE self
            (r"/users/search", UserSearchHandler),                       # GET search
            (r"/users/([a-z0-9_]{3,30})/stats", UserStatsHandler),       # GET stats
            (r"/users/([a-z0-9_]{3,30})", UserDetailHandler),            # GET public profile
            (r"/admin/users/([a-z0-9_]{3,30})", AdminUserHandler),       # PATCH/DELETE admin

            # Posts
            (r"/posts", PostsListHandler),                               # GET list (non-deleted)
            (r"/posts/search", PostsSearchHandler),                      # GET search
            (r"/posts/create", CreatePostHandler),                       # POST create (alias for POST /posts)
            (r"/posts/([A-Za-z0-9_-]+)", PostDetailHandler),             # GET by id
            (r"/posts/([A-Za-z0-9_-]+)/update", UpdatePostHandler),      # PATCH by id (author only)
            (r"/posts/([A-Za-z0-9_-]+)/delete", DeletePostHandler),      # DELETE by id (author/admin)
        ],
        debug=DEBUG,
    )

async def main():
    app = make_app()
    app.listen(PORT)
    print(f"Tornado server running on http://localhost:{PORT} (debug={DEBUG})")
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
