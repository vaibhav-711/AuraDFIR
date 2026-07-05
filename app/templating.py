from fastapi.templating import Jinja2Templates

from app import config

templates = Jinja2Templates(directory=str(config.BASE_DIR / "app" / "templates"))
templates.env.globals["APP_NAME"] = config.APP_NAME
