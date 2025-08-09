# main.py (minimal change)
import os, asyncio
from dotenv import load_dotenv
load_dotenv()

import tornado.web
from app.handlers.auth import RegisterHandler, LoginHandler


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

    ], debug=DEBUG)

async def main():
    app = make_app()
    app.listen(PORT)
    print(f"Tornado server running on http://localhost:{PORT} (debug={DEBUG})")
    await asyncio.Event().wait() 

if __name__ == "__main__":
    asyncio.run(main())
