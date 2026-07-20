"""
main.py — Whitewolf Security Network IDS web application.
"""
from pathlib import Path
from fastapi import Request, Form, Body

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app import database, auth
from app.ids_engine import engine, DANGEROUS_PORTS, PORT_SCAN_THRESHOLD

BASE_DIR = Path(__file__).parent

app = FastAPI(title="Whitewolf Security — Network IDS")

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

COMPANY = {
    "name": "Whitewolf Security",
    "address": "Osun State, Nigeria",
    "support_email": "clintonsam34@gmail.com",
    "tiktok": "https://www.tiktok.com/@anomaly_wolf",
}


@app.on_event("startup")
def on_startup():
    database.init_db()


def current_user(request: Request):
    return auth.get_user_from_request(request)


# ---------------------------------------------------------------- landing --

@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    user = current_user(request)
    return templates.TemplateResponse(
        request,
        "landing.html",
        {"company": COMPANY, "logged_in": user is not None},
    )


# --------------------------------------------------------------- register --

@app.get("/setup", response_class=HTMLResponse)
def setup_form(request: Request):
    if current_user(request):
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse(
        request, "setup.html", {"company": COMPANY, "error": None}
    )


@app.post("/setup")
def setup_submit(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
):
    error = None
    username = username.strip()
    email = email.strip()
    if len(username) < 3:
        error = "Username must be at least 3 characters."
    elif len(password) < 8:
        error = "Password must be at least 8 characters."
    elif database.get_user_by_username(username):
        error = "That username is already taken."

    if error:
        return templates.TemplateResponse(
            request, "setup.html", {"company": COMPANY, "error": error}, status_code=400
        )

    password_hash, salt = auth.hash_password(password)
    user_id = database.create_user(username, email, password_hash, salt)

    session_id, expires = auth.create_session(user_id)
    response = RedirectResponse("/dashboard", status_code=303)
    auth.set_session_cookie(response, session_id, expires)
    return response


# ------------------------------------------------------------------ login --

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if current_user(request):
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse(
        request, "login.html", {"company": COMPANY, "error": None}
    )


@app.post("/login")
def login_submit(
    request: Request, username: str = Form(...), password: str = Form(...)
):
    user = database.get_user_by_username(username.strip())
    if not user or not auth.verify_password(password, user["salt"], user["password_hash"]):
        return templates.TemplateResponse(
            request,
            "login.html",
            {"company": COMPANY, "error": "Incorrect username or password."},
            status_code=401,
        )

    session_id, expires = auth.create_session(user["id"])
    response = RedirectResponse("/dashboard", status_code=303)
    auth.set_session_cookie(response, session_id, expires)
    return response


@app.post("/logout")
def logout(request: Request):
    auth.logout(request)
    response = RedirectResponse("/login", status_code=303)
    auth.clear_session_cookie(response)
    return response


# -------------------------------------------------------------- dashboard --

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "company": COMPANY,
            "user": user,
            "dangerous_ports": DANGEROUS_PORTS,
            "threshold": PORT_SCAN_THRESHOLD,
        },
    )


# ---------------------------------------------------------------- settings --

@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, saved: str = None, error: str = None):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        request,
        "settings.html",
        {"company": COMPANY, "user": user, "saved": saved, "error": error},
    )


@app.post("/settings/profile")
def settings_profile(
    request: Request, email: str = Form(...), iface: str = Form(...)
):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    database.update_user_profile(user["id"], email.strip(), iface.strip() or "lo")
    return RedirectResponse("/settings?saved=profile", status_code=303)


@app.post("/settings/password")
def settings_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_new_password: str = Form(...),
):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    if not auth.verify_password(current_password, user["salt"], user["password_hash"]):
        return RedirectResponse("/settings?error=wrongpw", status_code=303)
    if len(new_password) < 8:
        return RedirectResponse("/settings?error=short", status_code=303)
    if new_password != confirm_new_password:
        return RedirectResponse("/settings?error=mismatch", status_code=303)

    password_hash, salt = auth.hash_password(new_password)
    database.update_user_password(user["id"], password_hash, salt)
    return RedirectResponse("/settings?saved=password", status_code=303)


# --------------------------------------------------------------------- api --

def require_api_user(request: Request):
    return current_user(request)


@app.post("/api/monitoring/start")
def start_monitoring(request: Request):
    user = require_api_user(request)
    if not user:
        return {"ok": False, "message": "Not authenticated."}
    
    print(f"[MAIN] Starting engine for user {user['id']}, iface={user.get('iface')}")
    ok, message = engine.start(user_id=user["id"], iface=user.get("iface"))
    status = engine.status()
    print(f"[MAIN] engine.start() returned ok={ok}, message={message}")
    print(f"[MAIN] engine.status() = {status}")
    
    return {"ok": ok, "message": message, "status": status}


@app.post("/api/monitoring/stop")
def stop_monitoring(request: Request):
    user = require_api_user(request)
    if not user:
        return {"ok": False, "message": "Not authenticated."}
    ok, message = engine.stop()
    return {"ok": ok, "message": message, "status": engine.status()}


@app.get("/api/status")
def status(request: Request):
    if not require_api_user(request):
        return {"ok": False, "message": "Not authenticated."}
    return engine.status()


@app.get("/api/alerts")
def alerts(request: Request, limit: int = 50):
    user = require_api_user(request)
    if not user:
        return []
    return database.get_recent_alerts(user_id=user["id"], limit=limit)


@app.get("/api/stats")
def stats(request: Request):
    user = require_api_user(request)
    if not user:
        return {}
    return database.get_stats(user_id=user["id"])


@app.get("/api/chart-data")
def chart_data(request: Request, minutes: int = 30):
    user = require_api_user(request)
    if not user:
        return {"labels": [], "values": []}
    return database.get_chart_data(user_id=user["id"], minutes=minutes)

@app.get("/api/interfaces")
def get_interfaces(request: Request):
    if not require_api_user(request):
        return {"ok": False, "message": "Not authenticated."}
    from app.ids_engine import get_available_interfaces
    return {"ok": True, "interfaces": get_available_interfaces()}


@app.post("/api/monitoring/start")
def start_monitoring(request: Request, body: dict = Body(default={})):
    user = require_api_user(request)
    if not user:
        return {"ok": False, "message": "Not authenticated."}
    
    iface = body.get("iface") or user.get("iface") or "lo"
    print(f"[MAIN] Starting engine for user {user['id']}, iface={iface}")
    ok, message = engine.start(user_id=user["id"], iface=iface)
    status = engine.status()
    print(f"[MAIN] engine.start() returned ok={ok}, message={message}")
    print(f"[MAIN] engine.status() = {status}")
    
    return {"ok": ok, "message": message, "status": status}
@app.post("/api/alerts/clear")
def clear_alerts(request: Request):
    user = require_api_user(request)
    if not user:
        return {"ok": False, "message": "Not authenticated."}
    database.clear_alerts(user_id=user["id"])
    return {"ok": True}
