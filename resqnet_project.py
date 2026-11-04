import csv
import hashlib
import hmac
import io
import json
import math
import os
import re
import secrets
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Request as FastAPIRequest, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field


APP_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.getenv("RESQNET_DB_PATH", APP_DIR / "resqnet_project.db"))
app = FastAPI(title="ResQNet | Response Operations")
SESSION_COOKIE = "resqnet_session"
SESSION_LIFETIME_SECONDS = 12 * 60 * 60
PASSWORD_HASH_ROUNDS = 310_000

TEAM_STATES = ("Available", "Deployed", "Unavailable")
INCIDENT_STATES = ("Pending", "Assigned", "EnRoute", "OnScene", "Resolved", "Cancelled")
PRIORITY_KEYWORDS = {
    "High": ("fire", "trapped", "collapse", "unconscious", "not breathing", "severe bleeding"),
    "Medium": ("injured", "flooding", "stranded", "missing person", "medical help", "evacuate"),
    "Low": ("food", "water", "shelter", "supplies", "power outage", "blocked road"),
}


def assess_priority(raw_report):
    text = raw_report.casefold()
    matched = [
        keyword
        for level in ("High", "Medium", "Low")
        for keyword in PRIORITY_KEYWORDS[level]
        if re.search(rf"(?<!\w){re.escape(keyword)}(?!\w)", text)
    ]
    if any(keyword in matched for keyword in PRIORITY_KEYWORDS["High"]):
        return "High", matched
    if any(keyword in matched for keyword in PRIORITY_KEYWORDS["Medium"]):
        return "Medium", matched
    if any(keyword in matched for keyword in PRIORITY_KEYWORDS["Low"]):
        return "Low", matched
    return "Medium", matched


class IncidentCreate(BaseModel):
    raw_report: str = Field(min_length=1, max_length=10000)
    user_lat: float = Field(ge=-90, le=90)
    user_lng: float = Field(ge=-180, le=180)
    needs: list[Literal["Medicine", "Food", "Water", "Clothing", "Blankets", "First aid", "Mobility support"]] = Field(default_factory=list, max_length=7)


class TeamCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    contact: Optional[str] = Field(default=None, max_length=200)
    location_lat: float = Field(ge=-90, le=90)
    location_lng: float = Field(ge=-180, le=180)


class ShelterCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    address: str = Field(min_length=1, max_length=300)
    contact: Optional[str] = Field(default=None, max_length=200)
    location_lat: float = Field(ge=-90, le=90)
    location_lng: float = Field(ge=-180, le=180)


class ShelterUpdate(BaseModel):
    status: Literal["Available", "Full", "Unavailable"]


class ResponderLocation(BaseModel):
    location_lat: float = Field(ge=-90, le=90)
    location_lng: float = Field(ge=-180, le=180)


class AccountRegistration(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=8, max_length=256)
    account_type: Literal["user", "rescuer"] = "user"


class AccountLogin(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)


class TeamUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    contact: Optional[str] = Field(default=None, max_length=200)
    responder_user_id: Optional[int] = None
    status: Optional[Literal["Available", "Deployed", "Unavailable"]] = None
    location_lat: Optional[float] = Field(default=None, ge=-90, le=90)
    location_lng: Optional[float] = Field(default=None, ge=-180, le=180)


class IncidentStatusUpdate(BaseModel):
    status: Literal["Pending", "Assigned", "EnRoute", "OnScene", "Resolved", "Cancelled"]


class IncidentAssignment(BaseModel):
    team_id: Optional[int] = Field(default=None, gt=0)


class UpdateHub:
    def __init__(self):
        self.clients = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.clients.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.clients.discard(websocket)

    async def broadcast(self, event):
        disconnected = []
        for client in self.clients:
            try:
                await client.send_json(event)
            except (RuntimeError, WebSocketDisconnect):
                disconnected.append(client)
        for client in disconnected:
            self.disconnect(client)


updates = UpdateHub()


def db_connection():
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def row_dict(row):
    if row is None:
        return None
    result = dict(row)
    if "needs" in result:
        try:
            result["needs"] = json.loads(result["needs"] or "[]")
        except (TypeError, ValueError):
            result["needs"] = []
    return result


def session_user(token):
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with closing(db_connection()) as connection:
        row = connection.execute(
            """SELECT u.user_id, u.name, u.email, u.role FROM user_sessions AS s
               JOIN users AS u ON u.user_id = s.user_id
               WHERE s.token_hash = ? AND s.expires_at > ?""",
            (token_hash, time.time()),
        ).fetchone()
    return row_dict(row)


def set_session_cookie(response, user_id, request):
    token = secrets.token_urlsafe(32)
    expires_at = time.time() + SESSION_LIFETIME_SECONDS
    with closing(db_connection()) as connection:
        with connection:
            connection.execute(
                "INSERT INTO user_sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (hashlib.sha256(token.encode()).hexdigest(), user_id, expires_at),
            )
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_LIFETIME_SECONDS,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax",
        path="/",
    )


def estimate_route(team, incident):
    start = (team["location_lat"], team["location_lng"])
    end = (incident["location_lat"], incident["location_lng"])
    if None in (*start, *end):
        return None, None, None, "unavailable"

    try:
        url = (
            "https://router.project-osrm.org/route/v1/driving/"
            f"{start[1]},{start[0]};{end[1]},{end[0]}"
            "?overview=false&alternatives=false&steps=false"
        )
        request = Request(url, headers={"User-Agent": "ResQNet/1.0"})
        with urlopen(request, timeout=4) as response:
            route_data = json.loads(response.read().decode("utf-8"))
        route = route_data["routes"][0]
        distance_km = route["distance"] / 1000
        duration_seconds = route["duration"]
        method = "road_route"
    except (OSError, URLError, ValueError, KeyError, IndexError):
        lat1, lat2 = math.radians(start[0]), math.radians(end[0])
        delta_lat = lat2 - lat1
        delta_lng = math.radians(end[1] - start[1])
        haversine = math.sin(delta_lat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lng / 2) ** 2
        distance_km = 6371 * 2 * math.asin(math.sqrt(haversine))
        duration_seconds = max(60, distance_km / 30 * 3600)
        method = "approx_straight_line"

    eta_minutes = max(1, math.ceil(duration_seconds / 60))
    estimated_arrival = (datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)).isoformat(timespec="minutes")
    return round(distance_km, 2), eta_minutes, estimated_arrival, method


def haversine_distance_km(start_lat, start_lng, end_lat, end_lng):
    lat1, lat2 = math.radians(start_lat), math.radians(end_lat)
    delta_lat = lat2 - lat1
    delta_lng = math.radians(end_lng - start_lng)
    haversine = math.sin(delta_lat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lng / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(haversine))


def nearest_available_shelter(connection, incident):
    if incident["location_lat"] is None or incident["location_lng"] is None:
        return None, None
    shelters = connection.execute(
        "SELECT * FROM shelters WHERE status = 'Available'"
    ).fetchall()
    if not shelters:
        return None, None
    shelter = min(
        shelters,
        key=lambda row: haversine_distance_km(
            incident["location_lat"], incident["location_lng"], row["location_lat"], row["location_lng"]
        ),
    )
    distance = haversine_distance_km(
        incident["location_lat"], incident["location_lng"], shelter["location_lat"], shelter["location_lng"]
    )
    return shelter, round(distance, 2)


def assign_nearest_available_team(connection, incident_id):
    incident = connection.execute(
        """SELECT * FROM incidents WHERE incident_id = ?
           AND status = 'Pending' AND assigned_team_id IS NULL""",
        (incident_id,),
    ).fetchone()
    if incident is None:
        return None
    teams = connection.execute(
        """SELECT t.*, COALESCE(l.location_lat, t.location_lat) AS current_lat,
                  COALESCE(l.location_lng, t.location_lng) AS current_lng
           FROM teams AS t
           LEFT JOIN responder_live_locations AS l
             ON l.team_id = t.team_id AND l.updated_at >= datetime('now', '-1 minute')
           WHERE t.status = 'Available'
             AND COALESCE(l.location_lat, t.location_lat) IS NOT NULL
             AND COALESCE(l.location_lng, t.location_lng) IS NOT NULL"""
    ).fetchall()
    if not teams:
        return None
    team = min(
        teams,
        key=lambda candidate: haversine_distance_km(
            incident["location_lat"], incident["location_lng"], candidate["current_lat"], candidate["current_lng"]
        ),
    )
    routing_team = dict(team)
    routing_team["location_lat"] = team["current_lat"]
    routing_team["location_lng"] = team["current_lng"]
    distance_km, eta_minutes, estimated_arrival, route_method = estimate_route(routing_team, incident)
    shelter, shelter_distance_km = nearest_available_shelter(connection, incident)
    connection.execute(
        """UPDATE incidents SET assigned_team_id = ?, status = 'Assigned',
           assigned_distance_km = ?, eta_minutes = ?, estimated_arrival = ?, route_method = ?,
           shelter_id = ?, shelter_distance_km = ?
           WHERE incident_id = ? AND status = 'Pending' AND assigned_team_id IS NULL""",
        (
            team["team_id"], distance_km, eta_minutes, estimated_arrival, route_method,
            shelter["shelter_id"] if shelter else None, shelter_distance_km, incident_id,
        ),
    )
    if connection.execute("SELECT changes()").fetchone()[0] == 0:
        return None
    connection.execute("UPDATE teams SET status = 'Deployed' WHERE team_id = ?", (team["team_id"],))
    return row_dict(connection.execute(
        """SELECT i.*, t.name AS assigned_team, t.contact AS team_contact,
                  s.name AS shelter_name, s.address AS shelter_address,
                  s.contact AS shelter_contact, s.location_lat AS shelter_lat,
                  s.location_lng AS shelter_lng
           FROM incidents AS i JOIN teams AS t ON t.team_id = i.assigned_team_id
           LEFT JOIN shelters AS s ON s.shelter_id = i.shelter_id
           WHERE i.incident_id = ?""",
        (incident_id,),
    ).fetchone())


def release_team_if_idle(connection, team_id):
    if team_id is None:
        return False
    active = connection.execute(
        """SELECT COUNT(*) FROM incidents WHERE assigned_team_id = ?
           AND status NOT IN ('Resolved', 'Cancelled')""",
        (team_id,),
    ).fetchone()[0]
    if active == 0:
        connection.execute("UPDATE teams SET status = 'Available' WHERE team_id = ?", (team_id,))
        return True
    return False


def auto_dispatch_pending_incidents(connection):
    pending_ids = connection.execute(
        """SELECT incident_id FROM incidents WHERE status = 'Pending' AND assigned_team_id IS NULL
           ORDER BY CASE severity WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END,
                    created_at, incident_id"""
    ).fetchall()
    assigned = []
    for incident in pending_ids:
        result = assign_nearest_available_team(connection, incident["incident_id"])
        if result is not None:
            assigned.append(result)
    return assigned


def init_database():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(db_connection()) as connection:
        with connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    password_salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'coordinator',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS user_sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    expires_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS teams (
                    team_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    contact TEXT,
                    location_lat REAL,
                    location_lng REAL,
                    responder_user_id INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
                    status TEXT NOT NULL DEFAULT 'Available',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS shelters (
                    shelter_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    address TEXT NOT NULL,
                    contact TEXT,
                    location_lat REAL NOT NULL,
                    location_lng REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'Available',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS responder_live_locations (
                    team_id INTEGER PRIMARY KEY REFERENCES teams(team_id) ON DELETE CASCADE,
                    location_lat REAL NOT NULL,
                    location_lng REAL NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    raw_report TEXT NOT NULL,
                    parsed_keywords TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT 'High',
                    status TEXT NOT NULL DEFAULT 'Pending',
                    location_lat REAL NOT NULL,
                    location_lng REAL NOT NULL,
                    assigned_team_id INTEGER REFERENCES teams(team_id) ON DELETE SET NULL,
                    needs TEXT NOT NULL DEFAULT '[]',
                    shelter_id INTEGER REFERENCES shelters(shelter_id) ON DELETE SET NULL,
                    shelter_distance_km REAL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            team_columns = {column["name"] for column in connection.execute("PRAGMA table_info(teams)")}
            if "responder_user_id" not in team_columns:
                connection.execute(
                    "ALTER TABLE teams ADD COLUMN responder_user_id INTEGER REFERENCES users(user_id) ON DELETE SET NULL"
                )
            user_columns = {column["name"] for column in connection.execute("PRAGMA table_info(users)")}
            if "role" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'coordinator'")
            incident_columns = {column["name"] for column in connection.execute("PRAGMA table_info(incidents)")}
            if "reporter_user_id" not in incident_columns:
                connection.execute(
                    "ALTER TABLE incidents ADD COLUMN reporter_user_id INTEGER REFERENCES users(user_id) ON DELETE SET NULL"
                )
            if "needs" not in incident_columns:
                connection.execute("ALTER TABLE incidents ADD COLUMN needs TEXT NOT NULL DEFAULT '[]'")
            if "shelter_id" not in incident_columns:
                connection.execute(
                    "ALTER TABLE incidents ADD COLUMN shelter_id INTEGER REFERENCES shelters(shelter_id) ON DELETE SET NULL"
                )
            if "shelter_distance_km" not in incident_columns:
                connection.execute("ALTER TABLE incidents ADD COLUMN shelter_distance_km REAL")
            for column, definition in (
                ("assigned_distance_km", "REAL"),
                ("eta_minutes", "INTEGER"),
                ("estimated_arrival", "TEXT"),
                ("route_method", "TEXT"),
            ):
                if column not in incident_columns:
                    connection.execute(f"ALTER TABLE incidents ADD COLUMN {column} {definition}")


@app.on_event("startup")
def startup():
    init_database()


@app.middleware("http")
async def require_login(request: FastAPIRequest, call_next):
    public_paths = {"/api/health", "/api/auth/register", "/api/auth/login", "/api/auth/session"}
    if request.url.path.startswith("/api/") and request.url.path not in public_paths:
        user = session_user(request.cookies.get(SESSION_COOKIE))
        if user is None:
            return JSONResponse(status_code=401, content={"detail": "Sign in to use ResQNet."})
        request.state.user = user
    return await call_next(request)


@app.exception_handler(sqlite3.IntegrityError)
async def handle_integrity_error(_, exc):
    if "users.email" in str(exc):
        detail = "This email is already registered. Sign in with it or use a different email."
    elif "teams.name" in str(exc):
        detail = "A rescue team already uses that name."
    else:
        detail = "That value is already in use."
    return JSONResponse(status_code=409, content={"detail": detail})


@app.post("/api/auth/register", status_code=201)
def register_account(account: AccountRegistration, request: FastAPIRequest, response: Response):
    email = account.email.strip().casefold()
    name = account.name.strip()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")
    if not name:
        raise HTTPException(status_code=422, detail="Enter your name.")
    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac("sha256", account.password.encode(), salt, PASSWORD_HASH_ROUNDS)
    with closing(db_connection()) as connection:
        with connection:
            first_account = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
            role = "coordinator" if first_account else (
                "rescuer_pending" if account.account_type == "rescuer" else "user"
            )
            cursor = connection.execute(
                """INSERT INTO users (name, email, password_salt, password_hash, role)
                   VALUES (?, ?, ?, ?, ?) RETURNING user_id, name, email, role""",
                (name, email, salt.hex(), password_hash.hex(), role),
            )
            user = row_dict(cursor.fetchone())
    set_session_cookie(response, user["user_id"], request)
    return {"user": user}


@app.post("/api/auth/login")
def login_account(account: AccountLogin, request: FastAPIRequest, response: Response):
    email = account.email.strip().casefold()
    with closing(db_connection()) as connection:
        row = connection.execute(
            "SELECT user_id, name, email, role, password_salt, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", account.password.encode(), bytes.fromhex(row["password_salt"]), PASSWORD_HASH_ROUNDS
    ).hex()
    if not hmac.compare_digest(password_hash, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    user = {key: row[key] for key in ("user_id", "name", "email", "role")}
    set_session_cookie(response, user["user_id"], request)
    return {"user": user}


@app.get("/api/auth/session")
def optional_session(request: FastAPIRequest):
    return {"user": session_user(request.cookies.get(SESSION_COOKIE))}


@app.get("/api/auth/me")
def current_account(request: FastAPIRequest):
    return {"user": request.state.user}


@app.post("/api/auth/logout")
def logout_account(request: FastAPIRequest, response: Response):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with closing(db_connection()) as connection:
            with connection:
                connection.execute(
                    "DELETE FROM user_sessions WHERE token_hash = ?",
                    (hashlib.sha256(token.encode()).hexdigest(),),
                )
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="lax")
    return {"message": "Signed out."}


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(DASHBOARD_HTML)


@app.get("/api/health")
def health():
    return {"status": "ok"}


def require_role(request, *allowed_roles):
    if request.state.user["role"] not in allowed_roles:
        raise HTTPException(status_code=403, detail="Your account cannot access this workspace feature.")


@app.get("/api/teams")
def get_teams(request: FastAPIRequest):
    role = request.state.user["role"]
    if role not in ("coordinator", "rescuer"):
        raise HTTPException(status_code=403, detail="Rescue team details are not available to this account.")
    sql = """SELECT t.team_id, t.name, t.contact, t.status, t.created_at, t.responder_user_id,
                    t.location_lat AS base_location_lat, t.location_lng AS base_location_lng,
                    COALESCE(l.location_lat, t.location_lat) AS location_lat,
                    COALESCE(l.location_lng, t.location_lng) AS location_lng,
                    CASE WHEN l.team_id IS NULL THEN 0 ELSE 1 END AS location_is_live,
                    l.updated_at AS location_updated_at,
                    u.name AS responder_name, u.email AS responder_email
             FROM teams AS t
             LEFT JOIN users AS u ON u.user_id = t.responder_user_id
                         LEFT JOIN responder_live_locations AS l
                             ON l.team_id = t.team_id AND l.updated_at >= datetime('now', '-1 minute')"""
    parameters = ()
    if role == "rescuer":
        sql += " WHERE u.user_id = ?"
        parameters = (request.state.user["user_id"],)
    sql += " ORDER BY t.name"
    with closing(db_connection()) as connection:
        rows = connection.execute(sql, parameters).fetchall()
    return [row_dict(row) for row in rows]


@app.get("/api/responders")
def get_responders(request: FastAPIRequest):
    require_role(request, "coordinator")
    with closing(db_connection()) as connection:
        rows = connection.execute(
            """SELECT u.user_id, u.name, u.email, u.role, t.team_id
               FROM users AS u LEFT JOIN teams AS t ON t.responder_user_id = u.user_id
               WHERE u.role IN ('rescuer_pending', 'rescuer') ORDER BY u.name"""
        ).fetchall()
    return [row_dict(row) for row in rows]


@app.post("/api/teams", status_code=201)
def create_team(team: TeamCreate, request: FastAPIRequest, background_tasks: BackgroundTasks):
    require_role(request, "coordinator")
    name = team.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Team name cannot be blank.")
    with closing(db_connection()) as connection:
        with connection:
            cursor = connection.execute(
                """INSERT INTO teams (name, contact, location_lat, location_lng)
                   VALUES (?, ?, ?, ?) RETURNING *""",
                (name, team.contact, team.location_lat, team.location_lng),
            )
            created = row_dict(cursor.fetchone())
            assigned_incidents = auto_dispatch_pending_incidents(connection)
    background_tasks.add_task(updates.broadcast, {"type": "team.created", "team": created})
    for incident in assigned_incidents:
        background_tasks.add_task(updates.broadcast, {"type": "incident.assigned", "incident": incident})
    return created


@app.patch("/api/teams/{team_id}")
def update_team(
    team_id: int,
    update: TeamUpdate,
    request: FastAPIRequest,
    background_tasks: BackgroundTasks,
):
    require_role(request, "coordinator")
    changes = update.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="Provide at least one field to update.")
    if "name" in changes and changes["name"] is not None:
        changes["name"] = changes["name"].strip()
        if not changes["name"]:
            raise HTTPException(status_code=422, detail="Team name cannot be blank.")
    columns = {"name", "contact", "responder_user_id", "status", "location_lat", "location_lng"}
    if not set(changes).issubset(columns):
        raise HTTPException(status_code=400, detail="Unsupported team field.")
    assignments = ", ".join(f"{column} = ?" for column in changes)
    with closing(db_connection()) as connection:
        with connection:
            current = connection.execute(
                "SELECT responder_user_id FROM teams WHERE team_id = ?", (team_id,)
            ).fetchone()
            if current is None:
                raise HTTPException(status_code=404, detail="Rescue team not found.")
            old_responder_id = current["responder_user_id"]
            new_responder_id = changes.get("responder_user_id", old_responder_id)
            if new_responder_id is not None and new_responder_id != old_responder_id:
                responder = connection.execute(
                    "SELECT role FROM users WHERE user_id = ?", (new_responder_id,)
                ).fetchone()
                if responder is None or responder["role"] not in ("rescuer_pending", "rescuer"):
                    raise HTTPException(status_code=404, detail="Rescuer account not found.")
                other_team = connection.execute(
                    "SELECT team_id FROM teams WHERE responder_user_id = ? AND team_id != ?",
                    (new_responder_id, team_id),
                ).fetchone()
                if other_team:
                    connection.execute(
                        "UPDATE teams SET responder_user_id = NULL WHERE team_id = ?",
                        (other_team["team_id"],),
                    )
            cursor = connection.execute(
                f"UPDATE teams SET {assignments} WHERE team_id = ? RETURNING *",
                (*changes.values(), team_id),
            )
            cursor.fetchone()
            if old_responder_id != new_responder_id:
                if old_responder_id:
                    connection.execute(
                        "UPDATE users SET role = 'rescuer_pending' WHERE user_id = ? AND role = 'rescuer'",
                        (old_responder_id,),
                    )
                if new_responder_id:
                    connection.execute(
                        "UPDATE users SET role = 'rescuer' WHERE user_id = ?",
                        (new_responder_id,),
                    )
            updated = row_dict(connection.execute(
                """SELECT t.*, u.name AS responder_name, u.email AS responder_email
                   FROM teams AS t LEFT JOIN users AS u ON u.user_id = t.responder_user_id
                   WHERE t.team_id = ?""",
                (team_id,),
            ).fetchone())
            assigned_incidents = auto_dispatch_pending_incidents(connection)
    background_tasks.add_task(updates.broadcast, {"type": "team.updated", "team": updated})
    for incident in assigned_incidents:
        background_tasks.add_task(updates.broadcast, {"type": "incident.assigned", "incident": incident})
    return updated


@app.delete("/api/teams/{team_id}", status_code=204)
def delete_team(team_id: int, request: FastAPIRequest, background_tasks: BackgroundTasks):
    require_role(request, "coordinator")
    with closing(db_connection()) as connection:
        with connection:
            team = connection.execute(
                "SELECT responder_user_id FROM teams WHERE team_id = ?", (team_id,)
            ).fetchone()
            if team is None:
                raise HTTPException(status_code=404, detail="Rescue team not found.")
            responder_user_id = team["responder_user_id"]
            connection.execute(
                """UPDATE incidents SET status = 'Pending', assigned_team_id = NULL,
                   assigned_distance_km = NULL, eta_minutes = NULL, estimated_arrival = NULL,
                   route_method = NULL, shelter_id = NULL, shelter_distance_km = NULL
                   WHERE assigned_team_id = ? AND status NOT IN ('Resolved', 'Cancelled')""",
                (team_id,),
            )
            connection.execute("DELETE FROM teams WHERE team_id = ?", (team_id,))
            if responder_user_id is not None:
                still_linked = connection.execute(
                    "SELECT COUNT(*) FROM teams WHERE responder_user_id = ?", (responder_user_id,)
                ).fetchone()[0]
                if still_linked == 0:
                    connection.execute(
                        "UPDATE users SET role = 'rescuer_pending' WHERE user_id = ? AND role = 'rescuer'",
                        (responder_user_id,),
                    )
            assigned_incidents = auto_dispatch_pending_incidents(connection)
    background_tasks.add_task(updates.broadcast, {"type": "team.deleted", "team_id": team_id})
    for incident in assigned_incidents:
        background_tasks.add_task(updates.broadcast, {"type": "incident.assigned", "incident": incident})


@app.get("/api/shelters")
def get_shelters(request: FastAPIRequest):
    require_role(request, "coordinator")
    with closing(db_connection()) as connection:
        rows = connection.execute("SELECT * FROM shelters ORDER BY name").fetchall()
    return [row_dict(row) for row in rows]


@app.post("/api/shelters", status_code=201)
def create_shelter(shelter: ShelterCreate, request: FastAPIRequest):
    require_role(request, "coordinator")
    name = shelter.name.strip()
    address = shelter.address.strip()
    if not name or not address:
        raise HTTPException(status_code=422, detail="Enter a shelter name and address.")
    with closing(db_connection()) as connection:
        with connection:
            cursor = connection.execute(
                """INSERT INTO shelters (name, address, contact, location_lat, location_lng)
                   VALUES (?, ?, ?, ?, ?) RETURNING *""",
                (name, address, shelter.contact, shelter.location_lat, shelter.location_lng),
            )
            created = row_dict(cursor.fetchone())
    return created


@app.patch("/api/shelters/{shelter_id}")
def update_shelter(shelter_id: int, update: ShelterUpdate, request: FastAPIRequest):
    require_role(request, "coordinator")
    with closing(db_connection()) as connection:
        with connection:
            cursor = connection.execute(
                "UPDATE shelters SET status = ? WHERE shelter_id = ? RETURNING *",
                (update.status, shelter_id),
            )
            updated = row_dict(cursor.fetchone())
            if updated is None:
                raise HTTPException(status_code=404, detail="Shelter not found.")
    return updated


@app.delete("/api/shelters/{shelter_id}", status_code=204)
def delete_shelter(shelter_id: int, request: FastAPIRequest):
    require_role(request, "coordinator")
    with closing(db_connection()) as connection:
        with connection:
            cursor = connection.execute("DELETE FROM shelters WHERE shelter_id = ?", (shelter_id,))
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Shelter not found.")


def recalculate_team_etas(connection, team):
    incidents = connection.execute(
        """SELECT incident_id, location_lat, location_lng FROM incidents
           WHERE assigned_team_id = ? AND status NOT IN ('Resolved', 'Cancelled')""",
        (team["team_id"],),
    ).fetchall()
    estimates = []
    for incident in incidents:
        distance_km, eta_minutes, estimated_arrival, route_method = estimate_route(team, incident)
        connection.execute(
            """UPDATE incidents SET assigned_distance_km = ?, eta_minutes = ?,
               estimated_arrival = ?, route_method = ? WHERE incident_id = ?""",
            (distance_km, eta_minutes, estimated_arrival, route_method, incident["incident_id"]),
        )
        estimates.append({
            "incident_id": incident["incident_id"],
            "eta_minutes": eta_minutes,
            "estimated_arrival": estimated_arrival,
        })
    return estimates


def expire_stale_responder_locations(connection):
    stale_teams = connection.execute(
        """SELECT t.* FROM teams AS t JOIN responder_live_locations AS l ON l.team_id = t.team_id
           WHERE l.updated_at < datetime('now', '-1 minute')"""
    ).fetchall()
    for team in stale_teams:
        connection.execute("DELETE FROM responder_live_locations WHERE team_id = ?", (team["team_id"],))
        recalculate_team_etas(connection, team)


@app.put("/api/responder/location")
def share_responder_location(
    location: ResponderLocation,
    request: FastAPIRequest,
    background_tasks: BackgroundTasks,
):
    require_role(request, "rescuer")
    with closing(db_connection()) as connection:
        with connection:
            team = connection.execute(
                "SELECT * FROM teams WHERE responder_user_id = ?",
                (request.state.user["user_id"],),
            ).fetchone()
            if team is None:
                raise HTTPException(status_code=403, detail="Your account is not linked to a rescue team.")
            connection.execute(
                """INSERT INTO responder_live_locations (team_id, location_lat, location_lng, updated_at)
                   VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                   ON CONFLICT(team_id) DO UPDATE SET location_lat = excluded.location_lat,
                   location_lng = excluded.location_lng, updated_at = CURRENT_TIMESTAMP""",
                (team["team_id"], location.location_lat, location.location_lng),
            )
            current_team = dict(team)
            current_team["location_lat"] = location.location_lat
            current_team["location_lng"] = location.location_lng
            estimates = recalculate_team_etas(connection, current_team)
            updated_at = connection.execute(
                "SELECT updated_at FROM responder_live_locations WHERE team_id = ?",
                (team["team_id"],),
            ).fetchone()["updated_at"]
    background_tasks.add_task(
        updates.broadcast,
        {"type": "incident.eta.updated", "team_id": team["team_id"]},
    )
    return {
        "location_lat": location.location_lat,
        "location_lng": location.location_lng,
        "updated_at": updated_at,
        "estimates": estimates,
    }


@app.delete("/api/responder/location")
def stop_responder_location(
    request: FastAPIRequest,
    background_tasks: BackgroundTasks,
):
    require_role(request, "rescuer")
    with closing(db_connection()) as connection:
        with connection:
            team = connection.execute(
                "SELECT * FROM teams WHERE responder_user_id = ?",
                (request.state.user["user_id"],),
            ).fetchone()
            if team is None:
                raise HTTPException(status_code=403, detail="Your account is not linked to a rescue team.")
            connection.execute(
                "DELETE FROM responder_live_locations WHERE team_id = ?", (team["team_id"],)
            )
            estimates = recalculate_team_etas(connection, team)
    background_tasks.add_task(
        updates.broadcast,
        {"type": "incident.eta.updated", "team_id": team["team_id"]},
    )
    return {"location_sharing": False, "estimates": estimates}


@app.get("/api/incidents")
def get_incidents(request: FastAPIRequest, status: Optional[str] = Query(default=None)):
    if status is not None and status not in INCIDENT_STATES:
        raise HTTPException(status_code=422, detail="Unknown incident status.")
    role = request.state.user["role"]
    if role not in ("coordinator", "user", "rescuer"):
        raise HTTPException(status_code=403, detail="Your rescuer account is awaiting coordinator approval.")
    sql = """SELECT i.*, t.name AS assigned_team, t.contact AS team_contact,
                    s.name AS shelter_name, s.address AS shelter_address,
                    s.contact AS shelter_contact, s.location_lat AS shelter_lat,
                    s.location_lng AS shelter_lng
             FROM incidents AS i
             LEFT JOIN teams AS t ON t.team_id = i.assigned_team_id
             LEFT JOIN shelters AS s ON s.shelter_id = i.shelter_id"""
    conditions = []
    parameters = []
    if role == "user":
        conditions.append("i.reporter_user_id = ?")
        parameters.append(request.state.user["user_id"])
    elif role == "rescuer":
        conditions.append("i.assigned_team_id IN (SELECT team_id FROM teams WHERE responder_user_id = ?)")
        parameters.append(request.state.user["user_id"])
    if status:
        conditions.append("i.status = ?")
        parameters.append(status)
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY i.created_at DESC, i.incident_id DESC"
    with closing(db_connection()) as connection:
        with connection:
            expire_stale_responder_locations(connection)
            rows = connection.execute(sql, tuple(parameters)).fetchall()
    return [row_dict(row) for row in rows]


@app.post("/api/incidents/report", status_code=201)
def create_incident(report: IncidentCreate, request: FastAPIRequest, background_tasks: BackgroundTasks):
    require_role(request, "user", "coordinator")
    raw_report = report.raw_report.strip()
    if not raw_report:
        raise HTTPException(status_code=422, detail="Describe the emergency in the report.")
    severity, matched_keywords = assess_priority(raw_report)
    with closing(db_connection()) as connection:
        with connection:
            cursor = connection.execute(
                     """INSERT INTO incidents (
                                             raw_report, parsed_keywords, severity, location_lat, location_lng, reporter_user_id, needs
                                     ) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING *""",
                     (raw_report, ", ".join(matched_keywords), severity, report.user_lat, report.user_lng,
                                 request.state.user["user_id"], json.dumps(list(dict.fromkeys(report.needs)))),
            )
            created = row_dict(cursor.fetchone())
            assigned = assign_nearest_available_team(connection, created["incident_id"])
            if assigned is not None:
                created = assigned
    background_tasks.add_task(updates.broadcast, {"type": "incident.created", "incident": created})
    return created


@app.patch("/api/incidents/{incident_id}/status")
def update_incident_status(
    incident_id: int,
    update: IncidentStatusUpdate,
    request: FastAPIRequest,
    background_tasks: BackgroundTasks,
):
    require_role(request, "coordinator", "rescuer")
    assigned_incidents = []
    with closing(db_connection()) as connection:
        with connection:
            if request.state.user["role"] == "rescuer":
                assigned = connection.execute(
                    """SELECT 1 FROM incidents AS i JOIN teams AS t
                       ON t.team_id = i.assigned_team_id
                       WHERE i.incident_id = ? AND t.responder_user_id = ?""",
                    (incident_id, request.state.user["user_id"]),
                ).fetchone()
                if assigned is None:
                    raise HTTPException(status_code=404, detail="Assigned incident not found.")
            cursor = connection.execute(
                """UPDATE incidents SET status = ? WHERE incident_id = ?
                   RETURNING incident_id, status, assigned_team_id""",
                (update.status, incident_id),
            )
            updated = row_dict(cursor.fetchone())
            if updated is None:
                raise HTTPException(status_code=404, detail="Incident not found.")
            if update.status in ("Resolved", "Cancelled") and updated["assigned_team_id"]:
                if release_team_if_idle(connection, updated["assigned_team_id"]):
                    assigned_incidents = auto_dispatch_pending_incidents(connection)
    background_tasks.add_task(updates.broadcast, {"type": "incident.status", "incident": updated})
    for incident in assigned_incidents:
        background_tasks.add_task(updates.broadcast, {"type": "incident.assigned", "incident": incident})
    return updated


@app.patch("/api/incidents/{incident_id}/assign")
def assign_incident(
    incident_id: int,
    assignment: IncidentAssignment,
    request: FastAPIRequest,
    background_tasks: BackgroundTasks,
):
    require_role(request, "coordinator")
    with closing(db_connection()) as connection:
        with connection:
            incident = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if incident is None:
                raise HTTPException(status_code=404, detail="Incident not found.")
            previous_team_id = incident["assigned_team_id"]
            if assignment.team_id is None:
                connection.execute(
                    """UPDATE incidents SET status = 'Pending', assigned_team_id = NULL,
                       assigned_distance_km = NULL, eta_minutes = NULL, estimated_arrival = NULL,
                       route_method = NULL, shelter_id = NULL, shelter_distance_km = NULL
                       WHERE incident_id = ?""",
                    (incident_id,),
                )
                release_team_if_idle(connection, previous_team_id)
            elif assignment.team_id != previous_team_id:
                team = connection.execute(
                    """SELECT t.*, COALESCE(l.location_lat, t.location_lat) AS current_lat,
                              COALESCE(l.location_lng, t.location_lng) AS current_lng
                       FROM teams AS t
                       LEFT JOIN responder_live_locations AS l
                         ON l.team_id = t.team_id AND l.updated_at >= datetime('now', '-1 minute')
                       WHERE t.team_id = ?""",
                    (assignment.team_id,),
                ).fetchone()
                if team is None:
                    raise HTTPException(status_code=404, detail="Rescue team not found.")
                if team["status"] == "Unavailable":
                    raise HTTPException(
                        status_code=409,
                        detail="That team is marked unavailable. Set it to Available before assigning.",
                    )
                if team["current_lat"] is None or team["current_lng"] is None:
                    raise HTTPException(
                        status_code=422,
                        detail="Set the team's base coordinates before assigning it.",
                    )
                routing_team = dict(team)
                routing_team["location_lat"] = team["current_lat"]
                routing_team["location_lng"] = team["current_lng"]
                distance_km, eta_minutes, estimated_arrival, route_method = estimate_route(routing_team, incident)
                shelter, shelter_distance_km = nearest_available_shelter(connection, incident)
                connection.execute(
                    """UPDATE incidents SET assigned_team_id = ?, status = 'Assigned',
                       assigned_distance_km = ?, eta_minutes = ?, estimated_arrival = ?, route_method = ?,
                       shelter_id = ?, shelter_distance_km = ?
                       WHERE incident_id = ?""",
                    (
                        assignment.team_id, distance_km, eta_minutes, estimated_arrival, route_method,
                        shelter["shelter_id"] if shelter else None, shelter_distance_km, incident_id,
                    ),
                )
                connection.execute(
                    "UPDATE teams SET status = 'Deployed' WHERE team_id = ?", (assignment.team_id,)
                )
                release_team_if_idle(connection, previous_team_id)
            updated = row_dict(connection.execute(
                """SELECT i.*, t.name AS assigned_team, t.contact AS team_contact,
                          s.name AS shelter_name, s.address AS shelter_address,
                          s.contact AS shelter_contact, s.location_lat AS shelter_lat,
                          s.location_lng AS shelter_lng
                   FROM incidents AS i LEFT JOIN teams AS t ON t.team_id = i.assigned_team_id
                   LEFT JOIN shelters AS s ON s.shelter_id = i.shelter_id
                   WHERE i.incident_id = ?""",
                (incident_id,),
            ).fetchone())
    background_tasks.add_task(updates.broadcast, {"type": "incident.assigned", "incident": updated})
    return updated


@app.get("/api/incidents/{incident_id}/report")
def incident_report(incident_id: int, request: FastAPIRequest):
    with closing(db_connection()) as connection:
        row = connection.execute(
                """SELECT i.*, t.name AS assigned_team, t.contact AS team_contact,
                             s.name AS shelter_name, s.address AS shelter_address,
                             s.contact AS shelter_contact, s.location_lat AS shelter_lat,
                             s.location_lng AS shelter_lng
                    FROM incidents AS i LEFT JOIN teams AS t ON t.team_id = i.assigned_team_id
                    LEFT JOIN shelters AS s ON s.shelter_id = i.shelter_id
               WHERE i.incident_id = ?""",
            (incident_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    report = row_dict(row)
    role = request.state.user["role"]
    if role == "user" and report["reporter_user_id"] != request.state.user["user_id"]:
        raise HTTPException(status_code=404, detail="Incident not found.")
    if role == "rescuer":
        with closing(db_connection()) as connection:
            assigned = connection.execute(
                "SELECT 1 FROM teams WHERE team_id = ? AND responder_user_id = ?",
                (report["assigned_team_id"], request.state.user["user_id"]),
            ).fetchone()
        if assigned is None:
            raise HTTPException(status_code=404, detail="Incident not found.")
    elif role not in ("user", "coordinator"):
        raise HTTPException(status_code=403, detail="Your rescuer account is awaiting coordinator approval.")
    return {"report": report}


@app.get("/api/reports/incidents.csv")
def export_incidents_csv(request: FastAPIRequest):
    require_role(request, "coordinator")
    with closing(db_connection()) as connection:
        rows = connection.execute(
            """SELECT i.incident_id, i.created_at, i.raw_report, i.parsed_keywords,
                      i.severity, i.status, i.location_lat, i.location_lng,
                      i.assigned_distance_km, i.eta_minutes, i.estimated_arrival, i.route_method,
                     i.needs, t.name AS assigned_team, s.name AS shelter_name,
                     s.address AS shelter_address, i.shelter_distance_km
                 FROM incidents AS i LEFT JOIN teams AS t ON t.team_id = i.assigned_team_id
                 LEFT JOIN shelters AS s ON s.shelter_id = i.shelter_id
               ORDER BY i.created_at DESC, i.incident_id DESC"""
        ).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(("incident_id", "created_at", "raw_report", "matched_keywords", "severity", "status", "latitude", "longitude", "route_distance_km", "eta_minutes", "estimated_arrival", "route_method", "needs", "assigned_team", "shelter_name", "shelter_address", "shelter_distance_km"))
    writer.writerows([tuple(row) for row in rows])
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=resqnet-emergency-reports.csv"},
    )


@app.websocket("/ws/incidents")
async def incident_websocket(websocket: WebSocket):
    user = session_user(websocket.cookies.get(SESSION_COOKIE))
    if user is None or user["role"] != "coordinator":
        await websocket.close(code=1008)
        return
    await updates.connect(websocket)
    try:
        await websocket.send_json({"type": "connected"})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        updates.disconnect(websocket)


DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%23164b3e'/%3E%3Ctext x='16' y='22' font-family='monospace' font-size='12' font-weight='700' fill='%23ffffff' text-anchor='middle'%3ERQ%3C/text%3E%3C/svg%3E">
<title>ResQNet | Response Operations</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;600;700&family=Newsreader:opsz,wght@6..72,500;6..72,600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/lucide@latest"></script>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
[hidden]{display:none!important}
:root{--ink:#172b28;--muted:#74817d;--line:#dfe6e1;--paper:#f3f6f2;--white:#fff;--forest:#164b3e;--forest2:#dcece4;--red:#c64b3d;--redbg:#fae7e2;--amber:#a86b16;--amberbg:#fff0d6;--blue:#36678e;--bluebg:#e4eff8;--sans:'DM Sans',sans-serif;--serif:'Newsreader',Georgia,serif;--mono:'DM Mono',monospace}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:14px var(--sans)}button,input,select,textarea{font:inherit}button{cursor:pointer}.shell{min-height:100vh}.topbar{height:64px;background:#fff;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 26px;position:sticky;top:0;z-index:20}.brand{display:flex;align-items:center;gap:11px;font-weight:700;letter-spacing:.2px}.brand-mark{width:34px;height:34px;background:var(--forest);color:#fff;display:grid;place-items:center;border-radius:4px;font:500 13px var(--mono)}.brand small{display:block;color:var(--muted);font-weight:500;font-size:11px;margin-top:1px}.top-right{display:flex;align-items:center;gap:20px;color:var(--muted);font-size:12px}.live-indicator{display:flex;align-items:center;gap:7px;color:var(--forest);font-weight:600}.pulse{width:8px;height:8px;background:#42a476;border-radius:50%;box-shadow:0 0 0 4px #e1f2e8}.top-date{font:11px var(--mono)}.layout{display:grid;grid-template-columns:220px minmax(0,1fr);max-width:1600px;margin:auto}.sidebar{border-right:1px solid var(--line);min-height:calc(100vh - 64px);padding:24px 14px;background:#f8faf7}.nav-label{font:10px var(--mono);text-transform:uppercase;color:#98a39e;padding:0 12px;margin:12px 0 8px;letter-spacing:1px}.nav-item{display:flex;align-items:center;gap:11px;color:#53635e;text-decoration:none;padding:11px 12px;border-radius:4px;margin:3px 0;cursor:pointer;font-weight:600;font-size:13px}.nav-item i{width:16px;height:16px}.nav-item:hover{background:#eaf0eb;color:var(--ink)}.nav-item.active{background:var(--forest2);color:var(--forest)}.side-foot{position:sticky;top:calc(100vh - 105px);margin:44px 6px 0;padding:14px 12px;border-top:1px solid var(--line);font-size:11px;color:var(--muted);line-height:1.6}.side-foot strong{color:var(--ink);font-weight:600}.main{padding:28px 32px 50px;min-width:0}.page-head{display:flex;justify-content:space-between;align-items:flex-end;margin:0 0 22px;gap:16px}.eyebrow{font:10px var(--mono);letter-spacing:1.1px;text-transform:uppercase;color:var(--forest);margin-bottom:5px}.page-head h1{font:500 31px var(--serif);letter-spacing:0;margin:0}.page-head p{margin:5px 0 0;color:var(--muted);font-size:12px}.primary,.secondary,.icon-button{border:0;border-radius:3px;display:inline-flex;align-items:center;justify-content:center;gap:8px;font-weight:600;transition:background .15s,transform .15s}.primary{background:var(--forest);color:white;padding:11px 15px}.primary:hover{background:#0e3b30;transform:translateY(-1px)}.secondary{background:#fff;border:1px solid var(--line);color:var(--ink);padding:9px 12px}.secondary:hover{background:#f4f7f3}.icon-button{width:34px;height:34px;background:transparent;color:#687771}.icon-button:hover{background:#edf2ee;color:var(--ink)}button i{width:16px;height:16px}.metric-strip{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));background:#fff;border:1px solid var(--line);margin-bottom:22px}.metric{padding:15px 18px;border-right:1px solid var(--line);position:relative}.metric:last-child{border:0}.metric-label{color:var(--muted);font-size:11px;font-weight:600}.metric-value{font:500 28px var(--serif);margin-top:6px}.metric-note{font-size:10px;color:var(--muted);margin-top:2px}.metric.alert .metric-value{color:var(--red)}.workspace-grid{display:grid;grid-template-columns:minmax(450px,1.25fr) minmax(320px,.85fr);gap:18px;align-items:start}.panel{background:#fff;border:1px solid var(--line);min-width:0}.panel-head{padding:15px 17px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line);min-height:57px}.panel-title{font-size:13px;font-weight:700}.panel-sub{font-size:11px;color:var(--muted);margin-top:3px}.panel-body{padding:0}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;text-align:left;white-space:nowrap}th{font:10px var(--mono);text-transform:uppercase;letter-spacing:.45px;color:#84918b;background:#fafbf9;padding:10px 12px;border-bottom:1px solid var(--line)}td{padding:11px 12px;border-bottom:1px solid #edf0ed;font-size:12px}tbody tr:last-child td{border-bottom:0}tbody tr:hover{background:#fbfcfa}.incident-id{font:11px var(--mono);color:#667771}.report-cell{max-width:230px;white-space:normal;line-height:1.4}.status-pill,.severity-pill,.team-pill{display:inline-flex;align-items:center;gap:6px;padding:4px 8px;border-radius:2px;font-size:10px;font-weight:700}.status-pill:before{content:'';width:6px;height:6px;border-radius:50%;background:currentColor}.s-Pending{color:var(--amber);background:var(--amberbg)}.s-Assigned,.s-EnRoute{color:var(--blue);background:var(--bluebg)}.s-OnScene{color:#824e94;background:#f1e6f4}.s-Resolved{color:var(--forest);background:var(--forest2)}.s-Cancelled{color:#69746f;background:#edf0ed}.sev-High{color:#a8372b;background:var(--redbg)}.sev-Medium{color:var(--amber);background:var(--amberbg)}.sev-Low{color:var(--forest);background:var(--forest2)}.table-select{border:1px solid var(--line);background:#fff;color:var(--ink);padding:6px 8px;border-radius:3px;font-size:11px;max-width:130px}.inline-actions{display:flex;align-items:center;gap:4px}.map-panel{position:sticky;top:82px}.map-head-note{font:10px var(--mono);color:var(--muted)}#map{height:340px;width:100%;background:#e9eee9;z-index:1}.map-legend{padding:12px 16px;display:flex;gap:15px;border-top:1px solid var(--line);font-size:10px;color:#65716d}.legend-item{display:flex;align-items:center;gap:6px}.legend-dot{width:8px;height:8px;border-radius:50%}.red-dot{background:var(--red)}.amber-dot{background:#d39b30}.green-dot{background:#328669}.empty{padding:34px 20px;text-align:center;color:var(--muted);font-size:12px}.empty strong{display:block;color:var(--ink);font:500 20px var(--serif);margin-bottom:6px}.view{display:none;animation:enter .24s ease-out}.view.active{display:block}@keyframes enter{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}.section-grid{display:grid;grid-template-columns:minmax(250px,.75fr) minmax(400px,1.45fr);gap:18px}.form-panel{padding:17px}.form-panel h2{font:500 21px var(--serif);margin:0 0 4px}.form-panel>p{color:var(--muted);font-size:11px;margin:0 0 18px}.field{display:flex;flex-direction:column;gap:6px;margin:0 0 13px}.field label{font-size:11px;font-weight:700;color:#4b5a55}.field input,.field select,.field textarea{width:100%;padding:10px;border:1px solid #d9e1db;border-radius:3px;background:#fff;color:var(--ink);outline:none}.field input:focus,.field select:focus,.field textarea:focus{border-color:#55907b;box-shadow:0 0 0 2px #dcece4}.field textarea{min-height:100px;resize:vertical;line-height:1.45}.field-hint{font-size:10px;color:var(--muted)}.coords{display:grid;grid-template-columns:1fr 1fr;gap:9px}.form-actions{display:flex;justify-content:space-between;align-items:center;margin-top:16px}.table-panel{overflow:hidden}.table-toolbar{display:flex;align-items:center;gap:8px}.filter-select{border:1px solid var(--line);border-radius:3px;background:#fff;padding:8px 10px;color:var(--ink);font-size:11px}.team-status{min-width:115px}.report-summary{font:12px/1.6 var(--sans);color:#596761;white-space:pre-wrap}.modal-backdrop{position:fixed;inset:0;background:#10221f88;display:none;align-items:center;justify-content:center;padding:20px;z-index:50}.modal-backdrop.open{display:flex}.modal{background:#fff;width:min(510px,100%);border-radius:4px;box-shadow:0 20px 80px #071a1533;max-height:92vh;overflow:auto;animation:enter .2s ease-out}.modal-head{display:flex;justify-content:space-between;align-items:center;padding:18px 20px;border-bottom:1px solid var(--line)}.modal-head h2{font:500 23px var(--serif);margin:0}.modal-content{padding:18px 20px}.modal-actions{display:flex;justify-content:flex-end;gap:9px;padding-top:8px}.toast{position:fixed;right:22px;bottom:22px;background:#183c33;color:#fff;padding:12px 16px;border-radius:3px;box-shadow:0 6px 25px #182c2633;z-index:80;font-size:12px;max-width:min(400px,calc(100vw - 44px));opacity:0;transform:translateY(8px);transition:.2s;pointer-events:none}.toast.show{opacity:1;transform:translateY(0)}.muted{color:var(--muted)}.mono{font-family:var(--mono)}.connection{font:10px var(--mono);color:var(--muted)}.connection.online{color:var(--forest)}.connection.offline{color:var(--red)}.mobile-nav{display:none}
@media(max-width:1050px){.layout{grid-template-columns:180px minmax(0,1fr)}.main{padding:24px 20px}.workspace-grid{grid-template-columns:1fr}.map-panel{position:static}.section-grid{grid-template-columns:1fr}.form-panel{max-width:none}}
@media(max-width:700px){.topbar{padding:0 14px;height:58px}.top-date{display:none}.layout{display:block}.sidebar{display:none}.main{padding:20px 13px 34px}.page-head{align-items:flex-start}.page-head h1{font-size:27px}.page-head p{max-width:250px;line-height:1.4}.metric-strip{grid-template-columns:repeat(2,1fr)}.metric{padding:12px;border-bottom:1px solid var(--line)}.metric:nth-child(2){border-right:0}.metric:nth-child(3),.metric:nth-child(4){border-bottom:0}.metric-value{font-size:24px}.workspace-grid{gap:12px}.panel-head{padding:13px}.table-wrap{overflow-x:auto}#map{height:280px}.mobile-nav{position:fixed;z-index:30;bottom:0;left:0;right:0;background:#fff;border-top:1px solid var(--line);display:flex;justify-content:space-around;padding:7px 4px calc(7px + env(safe-area-inset-bottom))}.mobile-nav .nav-item{display:flex;flex-direction:column;gap:3px;font-size:9px;padding:6px 9px;margin:0}.mobile-nav .nav-item i{width:17px;height:17px}.side-foot{display:none}.main{padding-bottom:90px}.page-head .primary{padding:10px 11px;font-size:11px}.page-head .primary span{display:none}.section-grid{gap:12px}.table-toolbar{flex-wrap:wrap;justify-content:flex-end}}
.auth-screen{min-height:100vh;display:grid;grid-template-columns:minmax(0,1.15fr) minmax(360px,.85fr);background:#f3f6f2}.auth-story{background:#164b3e;color:white;padding:clamp(32px,7vw,100px);display:flex;flex-direction:column;justify-content:space-between;min-height:100vh}.auth-story .brand-mark{background:#fff;color:#164b3e}.auth-story h1{font:500 clamp(34px,5vw,64px)/1.02 var(--serif);max-width:600px;margin:28px 0 14px}.auth-story p{max-width:460px;color:#d1e2d8;line-height:1.7}.auth-story-foot{font:11px var(--mono);color:#bbd2c5}.auth-panel{display:grid;place-items:center;padding:28px}.auth-card{width:min(410px,100%);background:#fff;border:1px solid var(--line);padding:28px}.auth-card h2{font:500 28px var(--serif);margin:0 0 6px}.auth-card>p{font-size:12px;line-height:1.5;color:var(--muted);margin:0 0 22px}.auth-toggle{display:grid;grid-template-columns:1fr 1fr;background:#eff3ef;padding:3px;border-radius:3px;margin-bottom:20px}.auth-toggle button{border:0;background:transparent;padding:9px;color:var(--muted);border-radius:2px;font-size:12px;font-weight:700}.auth-toggle button.active{background:#fff;color:var(--forest);box-shadow:0 1px 4px #182c2614}.account-control{display:flex;align-items:center;gap:10px}.account-name{color:var(--ink);font-size:12px;font-weight:600}.route-estimate{display:block;margin-top:4px;color:#51665c;font-size:10px;line-height:1.45;white-space:normal}.route-approx{color:var(--amber)}
@media(max-width:760px){.auth-screen{grid-template-columns:1fr}.auth-story{min-height:auto;padding:24px 22px 20px}.auth-story h1{font-size:34px;margin:18px 0 8px}.auth-story p{font-size:12px;margin:0}.auth-story-foot{display:none}.auth-panel{padding:20px 14px;align-items:start}.auth-card{padding:22px 18px}.account-name{display:none}}
.needs-options{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.needs-options label{display:flex;align-items:center;gap:7px;color:var(--ink);font-size:12px;font-weight:500}.needs-options input{width:auto;margin:0}
.nav-item{background:transparent;border:0;font-family:inherit;text-align:left;width:100%;line-height:1.25;font-size:13px;color:#53635e}.mobile-nav .nav-item{width:auto;text-align:center}:focus-visible{outline:2px solid #55907b;outline-offset:2px}.layout.single{grid-template-columns:1fr}.modal-open{overflow:hidden}.table-select.assign-team{max-width:200px}.detail-grid{display:grid;grid-template-columns:112px 1fr;gap:9px 14px;margin:0 0 16px}.detail-grid dt{font:10px var(--mono);text-transform:uppercase;letter-spacing:.6px;color:var(--muted);padding-top:2px}.detail-grid dd{margin:0;font-size:12px;line-height:1.5;overflow-wrap:anywhere}.detail-report{background:#f7f9f6;border-left:3px solid var(--forest);padding:12px 14px;font-size:12px;line-height:1.6;white-space:pre-wrap;margin:0 0 16px}.detail-actions{display:flex;flex-wrap:wrap;gap:8px;padding-top:4px}
@media(max-width:700px){.table-wrap:not(.incident-table) table{min-width:660px}.incident-table table{display:block;min-width:0}.incident-table thead{display:none}.incident-table tbody{display:block}.incident-table tbody tr{display:block;padding:13px 14px 14px;border-bottom:1px solid var(--line);white-space:normal}.incident-table tbody tr:last-child{border-bottom:0}.incident-table td{display:block;padding:0;border:0;white-space:normal}.incident-table td.report-cell{max-width:none;font-size:13px;line-height:1.5;margin:5px 0 9px}.incident-table td:nth-child(3){display:inline-block;margin:0 5px 6px 0}.incident-table td:nth-child(4){display:inline-block;margin:0 0 6px}.incident-table td:nth-child(5),.incident-table td:nth-child(6),.incident-table td:nth-child(7){margin-top:7px}.incident-table td[data-label]::before{content:attr(data-label);display:block;font:10px var(--mono);letter-spacing:.5px;text-transform:uppercase;color:var(--muted);margin-bottom:4px}.incident-table .table-select{max-width:none;width:100%;font-size:12px;padding:9px}.incident-table .inline-actions{gap:8px}.incident-table .inline-actions .table-select{flex:1;min-width:0}.incident-table .inline-actions .icon-button{flex:0 0 36px;height:36px;border:1px solid var(--line);border-radius:3px}.incident-table .route-estimate{margin-top:2px}}
</style>
</head>
<body>
<section id="auth-screen" class="auth-screen">
    <div class="auth-story"><div class="brand"><div class="brand-mark">RQ</div><div>ResQNet<small>Response operations</small></div></div><div><div class="eyebrow" style="color:#a8d0bb">Rescue coordination</div><h1>Every response starts with a clear picture.</h1><p>Coordinate teams, follow incidents live, and keep accurate emergency records in one place.</p></div><div class="auth-story-foot">RESQNET CONTROL / SECURE ACCESS</div></div>
    <div class="auth-panel"><form id="auth-form" class="auth-card"><h2 id="auth-title">Sign in</h2><p id="auth-description">Access your response operations workspace.</p><div class="auth-toggle"><button type="button" class="active" data-auth-mode="login">Sign in</button><button type="button" data-auth-mode="register">Create account</button></div><div class="field" id="auth-name-field" hidden><label for="auth-name">Full name</label><input id="auth-name" name="name" autocomplete="name" maxlength="120"></div><div class="field" id="auth-account-type" hidden><label for="account-type">I am registering as</label><select id="account-type" name="account_type"><option value="user">Someone needing help</option><option value="rescuer">Rescue responder</option></select><span class="field-hint">Responder accounts need to be linked to a rescue team by a coordinator.</span></div><div class="field"><label for="auth-email">Email</label><input id="auth-email" name="email" type="email" autocomplete="username" required maxlength="254"></div><div class="field"><label for="auth-password">Password</label><input id="auth-password" name="password" type="password" autocomplete="current-password" required minlength="8" maxlength="256"><span class="field-hint" id="password-hint" hidden>Use at least 8 characters.</span></div><button id="auth-submit" class="primary" type="submit" style="width:100%;justify-content:center">Sign in</button><div id="auth-error" class="field-hint" role="alert" style="color:var(--red);margin-top:12px"></div></form></div>
</section>
<div class="shell" hidden>
<header class="topbar">
  <div class="brand"><div class="brand-mark">RQ</div><div>ResQNet<small>Response operations</small></div></div>
    <div class="top-right"><span class="live-indicator"><span class="pulse"></span> <span id="live-label">Live operations</span></span><span id="clock" class="top-date"></span><div class="account-control"><span id="account-name" class="account-name"></span><button id="sign-out" class="secondary" type="button">Sign out</button></div></div>
</header>
<div class="layout">
<aside class="sidebar">
  <div class="nav-label">Workspace</div>
  <button type="button" class="nav-item active" data-view="overview"><i data-lucide="layout-dashboard"></i>Overview</button>
  <button type="button" class="nav-item" data-view="incidents"><i data-lucide="siren"></i>Incidents</button>
  <button type="button" class="nav-item" data-view="teams"><i data-lucide="users-round"></i>Rescue teams</button>
    <button type="button" class="nav-item" data-view="shelters"><i data-lucide="house"></i>Shelters</button>
  <div class="nav-label" style="margin-top:28px">Records</div>
  <button type="button" class="nav-item" data-view="reports"><i data-lucide="file-chart-column"></i>Reports</button>
  <div class="side-foot"><strong>ResQNet Control</strong><br>Incident coordination workspace<br><span id="socket-label" class="connection">Connecting to live feed...</span></div>
</aside>
<main class="main">
<section id="view-overview" class="view active">
    <div class="page-head"><div><div class="eyebrow">Operations / Overview</div><h1>Response operations</h1><p>Incident activity, team readiness, and field status in one place.</p></div><button class="primary" data-open-report aria-label="New emergency report" title="New emergency report"><i data-lucide="plus"></i><span>New emergency report</span></button></div>
  <div class="metric-strip" id="metrics"></div>
  <div class="workspace-grid">
    <section class="panel"><div class="panel-head"><div><div class="panel-title">Active incidents</div><div class="panel-sub">Latest reports and response status</div></div><button class="icon-button" data-view-link="incidents" title="View all incidents"><i data-lucide="arrow-up-right"></i></button></div><div class="panel-body" id="overview-incidents"></div></section>
    <section class="panel map-panel"><div class="panel-head"><div><div class="panel-title">Field locations</div><div class="panel-sub">Incident coordinates</div></div><span class="map-head-note" id="map-count">0 locations</span></div><div id="map"></div><div class="map-legend"><span class="legend-item"><i class="legend-dot red-dot"></i>High</span><span class="legend-item"><i class="legend-dot amber-dot"></i>Medium</span><span class="legend-item"><i class="legend-dot green-dot"></i>Low</span></div></section>
  </div>
</section>
<section id="view-incidents" class="view">
    <div class="page-head"><div><div class="eyebrow">Operations / Incidents</div><h1>Incident register</h1><p>Review reports, assign teams, and keep response status current.</p></div><button class="primary" data-open-report aria-label="New emergency report" title="New emergency report"><i data-lucide="plus"></i><span>New report</span></button></div>
  <section class="panel table-panel"><div class="panel-head"><div><div class="panel-title">Emergency reports</div><div class="panel-sub" id="incident-count">All incidents</div></div><div class="table-toolbar"><select id="status-filter" class="filter-select"><option value="">All statuses</option><option>Pending</option><option>Assigned</option><option>EnRoute</option><option>OnScene</option><option>Resolved</option><option>Cancelled</option></select></div></div><div class="panel-body" id="all-incidents"></div></section>
</section>
<section id="view-teams" class="view">
  <div class="page-head"><div><div class="eyebrow">Workspace / Rescue teams</div><h1>Team management</h1><p>Maintain responder contacts, field locations, and availability.</p></div></div>
  <div class="section-grid">
    <section class="panel form-panel"><h2>Register a team</h2><p>Add a response unit to the dispatch roster.</p><form id="team-form"><div class="field"><label for="team-name">Team name</label><input id="team-name" name="name" placeholder="North response unit" required maxlength="120"></div><div class="field"><label for="team-contact">Contact</label><input id="team-contact" name="contact" placeholder="Phone or radio channel"></div><div class="field"><label>Team's current GPS location</label><div class="coords"><input id="team-lat" name="location_lat" type="number" step="any" min="-90" max="90" placeholder="Latitude" required><input id="team-lng" name="location_lng" type="number" step="any" min="-180" max="180" placeholder="Longitude" required></div><span class="field-hint">Required for road distance and arrival estimates.</span></div><div class="form-actions"><button class="secondary" type="button" data-geolocate="team">Use device GPS</button><button class="primary" type="submit"><i data-lucide="user-plus"></i>Add team</button></div></form></section>
    <section class="panel table-panel"><div class="panel-head"><div><div class="panel-title">Rescue roster</div><div class="panel-sub" id="team-count">0 teams</div></div></div><div class="panel-body" id="team-table"></div></section>
  </div>
    <section class="panel table-panel responder-panel"><div class="panel-head"><div><div class="panel-title">Responder accounts</div><div class="panel-sub">Link a registered rescuer to their field team</div></div><span class="map-head-note" id="responder-count">0 accounts</span></div><div class="panel-body" id="responder-table"></div></section>
</section>
<section id="view-reports" class="view">
  <div class="page-head"><div><div class="eyebrow">Records / Reports</div><h1>Emergency reports</h1><p>Review generated incident records or export the full register.</p></div><a class="primary" href="/api/reports/incidents.csv"><i data-lucide="download"></i><span>Export CSV</span></a></div>
  <section class="panel table-panel"><div class="panel-head"><div><div class="panel-title">Report history</div><div class="panel-sub">Generated from submitted emergency reports</div></div></div><div class="panel-body" id="report-table"></div></section>
</section>
<section id="view-shelters" class="view">
    <div class="page-head"><div><div class="eyebrow">Workspace / Safe destinations</div><h1>Shelter directory</h1><p>Maintain safe locations used for responder recommendations.</p></div></div>
    <div class="section-grid">
        <section class="panel form-panel"><h2>Register a shelter</h2><p>Only available shelters are recommended during dispatch.</p><form id="shelter-form"><div class="field"><label for="shelter-name">Shelter name</label><input id="shelter-name" name="name" required maxlength="120" placeholder="Community relief center"></div><div class="field"><label for="shelter-address">Address or landmark</label><input id="shelter-address" name="address" required maxlength="300" placeholder="Street, area, or local landmark"></div><div class="field"><label for="shelter-contact">Contact</label><input id="shelter-contact" name="contact" maxlength="200" placeholder="Phone or on-site contact"></div><div class="field"><label>Shelter GPS location</label><div class="coords"><input id="shelter-lat" name="location_lat" type="number" step="any" min="-90" max="90" placeholder="Latitude" required><input id="shelter-lng" name="location_lng" type="number" step="any" min="-180" max="180" placeholder="Longitude" required></div></div><div class="form-actions"><button class="secondary" type="button" data-geolocate="shelter">Use device GPS</button><button class="primary" type="submit"><i data-lucide="plus"></i>Add shelter</button></div></form></section>
        <section class="panel table-panel"><div class="panel-head"><div><div class="panel-title">Available destinations</div><div class="panel-sub" id="shelter-count">0 shelters</div></div></div><div class="panel-body" id="shelter-table"></div></section>
    </div>
</section>
<section id="view-user" class="view">
    <div class="page-head"><div><div class="eyebrow">My account / Emergency reports</div><h1>My emergencies</h1><p>Submit a report and follow its response status.</p></div><button class="primary" data-open-report><i data-lucide="plus"></i><span>Report emergency</span></button></div>
    <section class="panel table-panel"><div class="panel-head"><div><div class="panel-title">Your reports</div><div class="panel-sub">Team assignment and arrival estimates appear here</div></div></div><div class="panel-body" id="user-incidents"></div></section>
</section>
<section id="view-rescuer" class="view">
    <div class="page-head"><div><div class="eyebrow">Responder workspace</div><h1 id="rescuer-title">My assignments</h1><p id="rescuer-description">Incidents assigned to your team.</p></div><div><button class="secondary" type="button" id="location-sharing-toggle">Share live GPS</button><div id="location-sharing-status" class="field-hint" role="status">Live ETA uses your team base until GPS sharing starts.</div></div></div>
    <section class="panel table-panel"><div class="panel-head"><div><div class="panel-title">Assigned incidents</div><div class="panel-sub">Update the status as your team responds</div></div></div><div class="panel-body" id="rescuer-incidents"></div></section>
</section>
</main>
</div>
<nav class="mobile-nav">
    <button type="button" class="nav-item active" data-view="overview"><i data-lucide="layout-dashboard"></i>Overview</button><button type="button" class="nav-item" data-view="incidents"><i data-lucide="siren"></i>Incidents</button><button type="button" class="nav-item" data-view="teams"><i data-lucide="users-round"></i>Teams</button><button type="button" class="nav-item" data-view="shelters"><i data-lucide="house"></i>Shelters</button><button type="button" class="nav-item" data-view="reports"><i data-lucide="file-chart-column"></i>Reports</button>
</nav>
</div>
<div id="report-modal" class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="report-title"><div class="modal"><div class="modal-head"><h2 id="report-title">New emergency report</h2><button class="icon-button" type="button" data-close-modal aria-label="Close"><i data-lucide="x"></i></button></div><form id="report-form" class="modal-content"><div class="field"><label for="report-text">What is happening?</label><textarea id="report-text" name="raw_report" required maxlength="10000" placeholder="Describe the emergency and assistance needed..."></textarea><span class="field-hint">Use clear, specific words about what you see and what help is needed.</span></div><div class="field"><label>Urgency keyword guide</label><div class="field-hint"><span class="severity-pill sev-High">High</span> fire, trapped, collapse, unconscious, not breathing, severe bleeding</div><div class="field-hint"><span class="severity-pill sev-Medium">Medium</span> injured, flooding, stranded, missing person, medical help, evacuate</div><div class="field-hint"><span class="severity-pill sev-Low">Low</span> food, water, shelter, supplies, power outage, blocked road</div><div><span id="priority-badge" class="severity-pill sev-Medium">Medium</span> <span id="priority-preview" class="field-hint">No listed keyword detected; starting at Medium for responder review.</span></div></div><div class="field"><label>Current location</label><div class="coords"><input id="report-lat" name="user_lat" type="number" step="any" min="-90" max="90" placeholder="Latitude" required><input id="report-lng" name="user_lng" type="number" step="any" min="-180" max="180" placeholder="Longitude" required></div></div><div class="form-actions"><button class="secondary" type="button" data-geolocate="report">Use device GPS</button><div class="modal-actions"><button class="secondary" type="button" data-close-modal>Cancel</button><button class="primary" type="submit"><i data-lucide="send"></i>Submit report</button></div></div></form></div></div>
<div id="detail-modal" class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="detail-title"><div class="modal"><div class="modal-head"><h2 id="detail-title">Incident report</h2><button class="icon-button" type="button" data-close-modal aria-label="Close"><i data-lucide="x"></i></button></div><div class="modal-content" id="detail-content"></div></div></div>
<div id="toast" class="toast" role="status"></div>
<script>
const state={teams:[],incidents:[],responders:[],shelters:[],map:null,markers:[],socket:null,userRole:null,locationWatchId:null,locationSharing:false,lastLocationSentAt:0,locationUpdateInFlight:false};
let authenticated=false;
let authMode='login';
const statusValues=['Pending','Assigned','EnRoute','OnScene','Resolved','Cancelled'];
const priorityKeywords={High:['fire','trapped','collapse','unconscious','not breathing','severe bleeding'],Medium:['injured','flooding','stranded','missing person','medical help','evacuate'],Low:['food','water','shelter','supplies','power outage','blocked road']};
const escapeHtml=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const toastMessage=message=>{const box=document.getElementById('toast');box.textContent=message;box.classList.add('show');clearTimeout(window.toastTimer);window.toastTimer=setTimeout(()=>box.classList.remove('show'),3200)};
async function api(path,options={}){const response=await fetch(path,{headers:{'Content-Type':'application/json',...(options.headers||{})},...options});if(!response.ok){let message=`Request failed (${response.status})`;try{message=(await response.json()).detail||message}catch{}throw new Error(message)}return response.status===204?null:response.json()}
function setView(name){document.querySelectorAll('.view').forEach(view=>view.classList.toggle('active',view.id===`view-${name}`));document.querySelectorAll('[data-view]').forEach(link=>{const active=link.dataset.view===name;link.classList.toggle('active',active);if(active)link.setAttribute('aria-current','page');else link.removeAttribute('aria-current')});const active=document.getElementById(`view-${name}`);if(name==='overview'&&state.map){setTimeout(()=>state.map.invalidateSize(),80)}if(active)window.scrollTo(0,0)}
function statusOptions(selected){return statusValues.map(status=>`<option value="${status}" ${status===selected?'selected':''}>${status}</option>`).join('')}
function teamOptions(selectedId){return `<option value="">Unassigned</option>`+(state.teams||[]).map(team=>`<option value="${team.team_id}" ${team.team_id===selectedId?'selected':''} ${team.status==='Unavailable'&&team.team_id!==selectedId?'disabled':''}>${escapeHtml(team.name)} — ${escapeHtml(team.status)}</option>`).join('')}
function severityClass(severity){return `sev-${['High','Medium','Low'].includes(severity)?severity:'Low'}`}
function previewPriority(){const text=document.getElementById('report-text').value.toLowerCase();const matched=Object.values(priorityKeywords).flat().filter(keyword=>new RegExp(`\\b${keyword.replace(/[.*+?^${}()|[\\]\\\\]/g,'\\\\$&')}\\b`,'i').test(text));const level=priorityKeywords.High.some(keyword=>matched.includes(keyword))?'High':priorityKeywords.Medium.some(keyword=>matched.includes(keyword))?'Medium':priorityKeywords.Low.some(keyword=>matched.includes(keyword))?'Low':'Medium';const badge=document.getElementById('priority-badge');badge.className=`severity-pill sev-${level}`;badge.textContent=level;document.getElementById('priority-preview').textContent=matched.length?`Matched: ${matched.join(', ')}`:'No listed keyword detected; starting at Medium for responder review.'}
function statusPill(status){return `<span class="status-pill s-${escapeHtml(status)}">${escapeHtml(status)}</span>`}
function routeArrival(item){if(item.assigned_team_id==null)return '<span class="field-hint">Awaiting team assignment</span>';if(item.eta_minutes==null)return '<span class="field-hint">ETA unavailable</span>';const arrival=new Date(item.estimated_arrival).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});return `<span class="route-estimate"><strong>${item.eta_minutes} min</strong> / arrival ~${arrival}</span>`}
function routeEstimate(item){const team=state.userRole==='rescuer'?state.teams[0]:null;let pickupLink='';if(team&&team.location_lat!=null&&team.location_lng!=null&&item.location_lat!=null&&item.location_lng!=null){const origin=`${Number(team.location_lat)},${Number(team.location_lng)}`;const destination=`${Number(item.location_lat)},${Number(item.location_lng)}`;const directions=`https://www.google.com/maps/dir/?api=1&origin=${encodeURIComponent(origin)}&destination=${encodeURIComponent(destination)}&travelmode=driving`;pickupLink=`<br><a href="${directions}" target="_blank" rel="noopener">Directions to pickup / ${team.location_is_live?'live GPS':'team base'}</a>`}if(item.eta_minutes==null||item.assigned_distance_km==null)return `<span class="field-hint">ETA unavailable</span>${pickupLink}`;const arrival=new Date(item.estimated_arrival).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});const approximate=item.route_method==='approx_straight_line';const locationLabel=team?(team.location_is_live?'live GPS':'team base'):approximate?'approximate straight-line':'road route';return `<span class="route-estimate ${approximate?'route-approx':''}"><strong>${Number(item.assigned_distance_km).toFixed(1)} km</strong> / ${item.eta_minutes} min<br>Arrival ~${arrival} / ${locationLabel}<br>Traffic not included${pickupLink}</span>`}
function incidentRows(incidents,compact=false){if(!incidents.length)return `<div class="empty"><strong>No incidents yet</strong>New emergency reports will appear here.</div>`;return `<div class="table-wrap incident-table"><table><thead><tr><th>Ref</th><th>Report</th><th>Priority</th><th>${compact?'Status / arrival':'Status'}</th>${compact?'':'<th>Team</th><th>Distance / arrival</th><th>Status control</th>'}</tr></thead><tbody>${incidents.map(item=>`<tr><td class="incident-id">#${item.incident_id}</td><td class="report-cell">${escapeHtml(item.raw_report)}</td><td><span class="severity-pill ${severityClass(item.severity)}">${escapeHtml(item.severity)}</span></td><td>${statusPill(item.status)}${compact?`<br>${routeArrival(item)}`:''}</td>${compact?'':`<td data-label="Team"><select class="table-select assign-team" data-id="${item.incident_id}" aria-label="Assign a rescue team to incident ${item.incident_id}" ${['Resolved','Cancelled'].includes(item.status)?'disabled title="Reopen the incident before reassigning"':''}>${teamOptions(item.assigned_team_id)}</select></td><td data-label="Distance / arrival">${routeEstimate(item)}</td><td data-label="Update status"><div class="inline-actions"><select class="table-select status-change" data-id="${item.incident_id}" aria-label="Update incident ${item.incident_id} status">${statusOptions(item.status)}</select><button type="button" class="icon-button view-incident" data-id="${item.incident_id}" title="View report" aria-label="View report ${item.incident_id}"><i data-lucide="file-text"></i></button></div></td>`}</tr>`).join('')}</tbody></table></div>`}
function renderMetrics(){const open=state.incidents.filter(item=>!['Resolved','Cancelled'].includes(item.status)).length;const pending=state.incidents.filter(item=>item.status==='Pending').length;const activeTeams=state.teams.filter(team=>team.status==='Deployed').length;const available=state.teams.filter(team=>team.status==='Available').length;document.getElementById('metrics').innerHTML=`<div class="metric alert"><div class="metric-label">Open incidents</div><div class="metric-value">${open}</div><div class="metric-note">${pending} awaiting assignment</div></div><div class="metric"><div class="metric-label">Teams available</div><div class="metric-value">${available}</div><div class="metric-note">Ready for dispatch</div></div><div class="metric"><div class="metric-label">Teams deployed</div><div class="metric-value">${activeTeams}</div><div class="metric-note">Currently in the field</div></div><div class="metric"><div class="metric-label">Reports logged</div><div class="metric-value">${state.incidents.length}</div><div class="metric-note">All recorded incidents</div></div>`}
function renderTeams(){document.getElementById('team-count').textContent=`${state.teams.length} ${state.teams.length===1?'team':'teams'}`;const target=document.getElementById('team-table');if(!state.teams.length){target.innerHTML='<div class="empty"><strong>No teams registered</strong>Add a response unit to start building the roster.</div>';return}target.innerHTML=`<div class="table-wrap"><table><thead><tr><th>Team</th><th>Contact</th><th>Base coordinates</th><th>Status</th><th></th></tr></thead><tbody>${state.teams.map(team=>`<tr><td><strong>${escapeHtml(team.name)}</strong></td><td>${escapeHtml(team.contact||'--')}</td><td class="mono">${team.location_lat==null?'--':`${Number(team.location_lat).toFixed(4)}, ${Number(team.location_lng).toFixed(4)}`}</td><td><select class="table-select team-status" data-id="${team.team_id}" aria-label="Team ${escapeHtml(team.name)} status">${['Available','Deployed','Unavailable'].map(status=>`<option ${team.status===status?'selected':''}>${status}</option>`).join('')}</select></td><td><button class="icon-button delete-team" data-id="${team.team_id}" title="Remove team" aria-label="Remove ${escapeHtml(team.name)}"><i data-lucide="trash-2"></i></button></td></tr>`).join('')}</tbody></table></div>`;refreshIcons()}
function renderShelters(){const target=document.getElementById('shelter-table');document.getElementById('shelter-count').textContent=`${state.shelters.length} ${state.shelters.length===1?'shelter':'shelters'}`;if(!state.shelters.length){target.innerHTML='<div class="empty"><strong>No shelters registered</strong>Add safe destinations for responders to use after pickup.</div>';return}target.innerHTML=`<div class="table-wrap"><table><thead><tr><th>Shelter</th><th>Address</th><th>Contact</th><th>Availability</th><th></th></tr></thead><tbody>${state.shelters.map(shelter=>`<tr><td><strong>${escapeHtml(shelter.name)}</strong></td><td>${escapeHtml(shelter.address)}<br><span class="mono">${Number(shelter.location_lat).toFixed(4)}, ${Number(shelter.location_lng).toFixed(4)}</span></td><td>${escapeHtml(shelter.contact||'--')}</td><td><select class="table-select shelter-status" data-id="${shelter.shelter_id}" aria-label="Update ${escapeHtml(shelter.name)} availability">${['Available','Full','Unavailable'].map(status=>`<option ${shelter.status===status?'selected':''}>${status}</option>`).join('')}</select></td><td><button class="icon-button delete-shelter" data-id="${shelter.shelter_id}" title="Remove shelter" aria-label="Remove ${escapeHtml(shelter.name)}"><i data-lucide="trash-2"></i></button></td></tr>`).join('')}</tbody></table></div>`;refreshIcons()}
function renderResponders(){const target=document.getElementById('responder-table');document.getElementById('responder-count').textContent=`${state.responders.length} ${state.responders.length===1?'account':'accounts'}`;if(!state.responders.length){target.innerHTML='<div class="empty"><strong>No responder accounts yet</strong>Rescuers can select the responder account type when they register.</div>';return}target.innerHTML=`<div class="table-wrap"><table><thead><tr><th>Responder</th><th>Email</th><th>Account</th><th>Team</th></tr></thead><tbody>${state.responders.map(responder=>`<tr><td><strong>${escapeHtml(responder.name)}</strong></td><td>${escapeHtml(responder.email)}</td><td>${responder.role==='rescuer'?'Active':'Awaiting team'}</td><td><select class="table-select responder-team" data-user-id="${responder.user_id}" aria-label="Link ${escapeHtml(responder.name)} to a rescue team"><option value="">Not linked</option>${state.teams.map(team=>`<option value="${team.team_id}" ${responder.team_id===team.team_id?'selected':''}>${escapeHtml(team.name)}</option>`).join('')}</select></td></tr>`).join('')}</tbody></table></div>`}
function necessityList(item){const needs=Array.isArray(item.needs)?item.needs:[];return needs.length?needs.map(escapeHtml).join(', '):'No specific needs listed'}
function shelterGuidance(item){if(!item.shelter_name||item.shelter_lat==null||item.shelter_lng==null)return '<span class="field-hint">No available shelter registered; contact operations before transport.</span>';const origin=`${Number(item.location_lat)},${Number(item.location_lng)}`;const destination=`${Number(item.shelter_lat)},${Number(item.shelter_lng)}`;const directions=`https://www.google.com/maps/dir/?api=1&origin=${encodeURIComponent(origin)}&destination=${encodeURIComponent(destination)}&travelmode=driving`;const distance=item.shelter_distance_km==null?'':`<br>${Number(item.shelter_distance_km).toFixed(1)} km straight-line`;return `<strong>${escapeHtml(item.shelter_name)}</strong><br>${escapeHtml(item.shelter_address||'Address not listed')}${distance}<br><a href="${directions}" target="_blank" rel="noopener">Directions from pickup</a>${item.shelter_contact?`<br>${escapeHtml(item.shelter_contact)}`:''}`}
function renderUserWorkspace(){const target=document.getElementById('user-incidents');if(!state.incidents.length){target.innerHTML='<div class="empty"><strong>No emergency reports yet</strong>Use Report emergency to ask for help.</div>';return}target.innerHTML=`<div class="table-wrap"><table><thead><tr><th>Ref</th><th>Emergency</th><th>Needs</th><th>Status</th><th>Response team</th><th>Arrival estimate</th><th>Shelter destination</th></tr></thead><tbody>${state.incidents.map(item=>`<tr><td class="incident-id">#${item.incident_id}</td><td class="report-cell">${escapeHtml(item.raw_report)}</td><td>${necessityList(item)}</td><td>${statusPill(item.status)}</td><td>${escapeHtml(item.assigned_team||'Awaiting assignment')}${item.team_contact?`<br>${escapeHtml(item.team_contact)}`:''}</td><td>${routeArrival(item)}</td><td>${shelterGuidance(item)}</td></tr>`).join('')}</tbody></table></div>`}
function renderResponderWorkspace(){const target=document.getElementById('rescuer-incidents');const canShare=state.userRole==='rescuer'&&state.teams.length>0;document.querySelectorAll('#location-sharing-toggle,#location-sharing-status').forEach(node=>node.hidden=!canShare);if(!canShare){document.getElementById('rescuer-title').textContent='Responder account pending';document.getElementById('rescuer-description').textContent='A coordinator needs to link your account to a rescue team before assignments appear.';target.innerHTML='<div class="empty"><strong>Awaiting team assignment</strong>Your assigned incidents will appear here after a coordinator links you to a team.</div>';return}const team=state.teams[0];document.getElementById('rescuer-title').textContent=team?team.name:'My assignments';document.getElementById('rescuer-description').textContent=team?`${team.status} / ${team.contact||'No team contact listed'}`:'Incidents assigned to your team.';if(!state.incidents.length){target.innerHTML='<div class="empty"><strong>No active assignments</strong>New incidents assigned to your team will appear here.</div>';return}target.innerHTML=`<div class="table-wrap"><table><thead><tr><th>Ref</th><th>Emergency</th><th>Needs to bring</th><th>Pickup location</th><th>Shelter destination</th><th>Status</th></tr></thead><tbody>${state.incidents.map(item=>`<tr><td class="incident-id">#${item.incident_id}</td><td class="report-cell">${escapeHtml(item.raw_report)}<br><span class="severity-pill ${severityClass(item.severity)}">${escapeHtml(item.severity)}</span></td><td>${necessityList(item)}</td><td class="mono">${Number(item.location_lat).toFixed(4)}, ${Number(item.location_lng).toFixed(4)}<br>${routeEstimate(item)}</td><td>${shelterGuidance(item)}</td><td><select class="table-select status-change" data-id="${item.incident_id}" aria-label="Update incident ${item.incident_id} status">${statusOptions(item.status)}</select></td></tr>`).join('')}</tbody></table></div>`}
function renderReports(){const target=document.getElementById('report-table');if(!state.incidents.length){target.innerHTML='<div class="empty"><strong>No reports generated</strong>Submitted emergency reports will be available here.</div>';return}target.innerHTML=`<div class="table-wrap"><table><thead><tr><th>Report</th><th>Created</th><th>Description</th><th>Priority</th><th>Status</th><th>Assigned team</th><th>Distance / arrival</th><th></th></tr></thead><tbody>${state.incidents.map(item=>`<tr><td class="incident-id">#${item.incident_id}</td><td class="mono">${escapeHtml(new Date(item.created_at+'Z').toLocaleString())}</td><td class="report-cell">${escapeHtml(item.raw_report)}</td><td><span class="severity-pill ${severityClass(item.severity)}">${escapeHtml(item.severity)}</span></td><td>${statusPill(item.status)}</td><td>${escapeHtml(item.assigned_team||'Unassigned')}</td><td>${routeEstimate(item)}</td><td><button class="icon-button download-report" data-id="${item.incident_id}" title="View report" aria-label="View report ${item.incident_id}"><i data-lucide="file-text"></i></button></td></tr>`).join('')}</tbody></table></div>`;refreshIcons()}
function renderMap(){if(!window.L)return;const container=document.getElementById('map');if(!container)return;if(!state.map){state.map=L.map(container,{zoomControl:true}).setView([17.385,78.4867],11);L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:19,attribution:'&copy; OpenStreetMap'}).addTo(state.map)}state.markers.forEach(marker=>marker.remove());state.markers=[];const points=[];state.incidents.forEach(item=>{if(item.location_lat==null||item.location_lng==null)return;const color=item.severity==='High'?'#c64b3d':item.severity==='Medium'?'#d39b30':'#328669';const marker=L.circleMarker([item.location_lat,item.location_lng],{radius:8,color:'#fff',weight:2,fillColor:color,fillOpacity:.95}).addTo(state.map).bindPopup(`<strong>#${item.incident_id} ${escapeHtml(item.severity)}</strong><br>${escapeHtml(item.raw_report)}<br>${escapeHtml(item.status)}`);state.markers.push(marker);points.push([item.location_lat,item.location_lng])});state.teams.filter(team=>team.location_lat!=null&&team.location_lng!=null).forEach(team=>{const marker=L.circleMarker([team.location_lat,team.location_lng],{radius:6,color:'#fff',weight:2,fillColor:'#315c83',fillOpacity:.9}).addTo(state.map).bindPopup(`<strong>${escapeHtml(team.name)}</strong><br>${escapeHtml(team.status)}`);state.markers.push(marker);points.push([team.location_lat,team.location_lng])});document.getElementById('map-count').textContent=`${points.length} locations`;if(points.length===1)state.map.setView(points[0],13);else if(points.length>1)state.map.fitBounds(points,{padding:[28,28],maxZoom:13});setTimeout(()=>state.map.invalidateSize(),60)}
function renderAll(){renderMetrics();document.getElementById('overview-incidents').innerHTML=incidentRows(state.incidents.filter(item=>!['Resolved','Cancelled'].includes(item.status)).slice(0,8),true);document.getElementById('all-incidents').innerHTML=incidentRows(state.incidents);document.getElementById('incident-count').textContent=`${state.incidents.length} recorded`;renderTeams();renderReports();renderMap();refreshIcons()}
async function loadData(){if(!authenticated)return;try{if(state.userRole==='coordinator'){const [teams,incidents,responders,shelters]=await Promise.all([api('/api/teams'),api('/api/incidents'),api('/api/responders'),api('/api/shelters')]);state.teams=teams;state.incidents=incidents;state.responders=responders;state.shelters=shelters;renderAll();renderResponders();renderShelters();return}if(state.userRole==='user'){state.incidents=await api('/api/incidents');renderUserWorkspace();return}if(state.userRole==='rescuer'){const [teams,incidents]=await Promise.all([api('/api/teams'),api('/api/incidents')]);state.teams=teams;state.incidents=incidents;renderResponderWorkspace();return}state.teams=[];state.incidents=[];renderResponderWorkspace()}catch(error){toastMessage(error.message)}}
function setLocationShareStatus(message){document.getElementById('location-sharing-status').textContent=message;document.getElementById('location-sharing-toggle').textContent=state.locationSharing?'Stop live GPS':'Share live GPS'}
async function sendResponderLocation(position){if(state.locationUpdateInFlight||Date.now()-state.lastLocationSentAt<10000)return;state.locationUpdateInFlight=true;state.lastLocationSentAt=Date.now();try{const result=await api('/api/responder/location',{method:'PUT',body:JSON.stringify({location_lat:position.coords.latitude,location_lng:position.coords.longitude})});const updated=result.estimates.length;setLocationShareStatus(`Live GPS active / ${updated} ${updated===1?'ETA':'ETAs'} refreshed at ${new Date(result.updated_at+'Z').toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}`);await loadData()}catch(error){setLocationShareStatus(error.message)}finally{state.locationUpdateInFlight=false}}
function startResponderLocationShare(){if(state.userRole!=='rescuer'||!state.teams.length){toastMessage('Connect to a rescue team before sharing live GPS.');return}if(!navigator.geolocation){setLocationShareStatus('GPS is not available in this browser.');return}state.locationSharing=true;state.lastLocationSentAt=0;setLocationShareStatus('Waiting for GPS fix...');state.locationWatchId=navigator.geolocation.watchPosition(sendResponderLocation,error=>{state.locationSharing=false;if(state.locationWatchId!==null)navigator.geolocation.clearWatch(state.locationWatchId);state.locationWatchId=null;setLocationShareStatus(error.code===1?'GPS permission was denied.':'GPS signal unavailable. Check device location and try again.')},{enableHighAccuracy:true,maximumAge:5000,timeout:20000})}
async function stopResponderLocationShare(){if(state.locationWatchId!==null)navigator.geolocation.clearWatch(state.locationWatchId);state.locationWatchId=null;state.locationSharing=false;state.lastLocationSentAt=0;try{await api('/api/responder/location',{method:'DELETE'});setLocationShareStatus('Live GPS stopped / ETA now uses the team base.');await loadData()}catch(error){setLocationShareStatus(error.message)}}
function refreshIcons(){if(window.lucide)lucide.createIcons()}
function setAuthMode(mode){authMode=mode;const registering=mode==='register';document.getElementById('auth-title').textContent=registering?'Create your account':'Sign in';document.getElementById('auth-description').textContent=registering?'Register to report emergencies or join a rescue team.':'Access your ResQNet workspace.';document.getElementById('auth-name-field').hidden=!registering;document.getElementById('auth-account-type').hidden=!registering;document.getElementById('auth-name').required=registering;document.getElementById('auth-password').autocomplete=registering?'new-password':'current-password';document.getElementById('password-hint').hidden=!registering;document.getElementById('auth-submit').textContent=registering?'Create account':'Sign in';document.getElementById('auth-error').textContent='';document.querySelectorAll('[data-auth-mode]').forEach(button=>button.classList.toggle('active',button.dataset.authMode===mode))}
function showWorkspace(user){authenticated=true;state.userRole=user.role;document.getElementById('auth-screen').hidden=true;document.querySelector('.shell').hidden=false;document.getElementById('account-name').textContent=user.name;const coordinator=user.role==='coordinator';document.getElementById('live-label').textContent=coordinator?'Live operations':'Auto-refresh';document.querySelector('.layout').classList.toggle('single',!coordinator);document.querySelectorAll('#location-sharing-toggle,#location-sharing-status').forEach(node=>node.hidden=user.role!=='rescuer');document.querySelector('.sidebar').hidden=!coordinator;document.querySelector('.mobile-nav').hidden=!coordinator;document.querySelectorAll('#view-overview,#view-incidents,#view-teams,#view-shelters,#view-reports').forEach(view=>view.hidden=!coordinator);setView(coordinator?'overview':user.role==='user'?'user':'rescuer');loadData();if(coordinator){clearInterval(window.roleRefreshTimer);connectLive()}else{clearInterval(window.roleRefreshTimer);window.roleRefreshTimer=setInterval(loadData,15000)}}
async function restoreSession(){try{const result=await api('/api/auth/session');if(result.user){showWorkspace(result.user);return}}catch{}authenticated=false;document.getElementById('auth-screen').hidden=false;document.querySelector('.shell').hidden=true}
function connectLive(){if(!authenticated)return;const scheme=location.protocol==='https:'?'wss':'ws';const socket=new WebSocket(`${scheme}://${location.host}/ws/incidents`);state.socket=socket;socket.onopen=()=>{document.querySelectorAll('.connection').forEach(node=>{node.textContent='Live feed connected';node.className='connection online'})};socket.onmessage=event=>{const message=JSON.parse(event.data);if(message.type!=='connected')loadData()};socket.onclose=()=>{if(!authenticated)return;document.querySelectorAll('.connection').forEach(node=>{node.textContent='Live feed reconnecting';node.className='connection offline'});setTimeout(connectLive,2500)};socket.onerror=()=>socket.close()}
setInterval(async()=>{if(!authenticated||state.userRole!=='rescuer_pending')return;try{const current=await api('/api/auth/me');if(current.user.role==='rescuer')showWorkspace(current.user)}catch{}},15000);
function geolocate(prefix){if(!navigator.geolocation){toastMessage('Device location is not available in this browser.');return}navigator.geolocation.getCurrentPosition(position=>{document.getElementById(`${prefix}-lat`).value=position.coords.latitude.toFixed(6);document.getElementById(`${prefix}-lng`).value=position.coords.longitude.toFixed(6);toastMessage('Current coordinates filled in.')},()=>toastMessage('Location permission was unavailable.'),{enableHighAccuracy:true,timeout:10000})}
document.querySelectorAll('[data-auth-mode]').forEach(button=>button.addEventListener('click',()=>setAuthMode(button.dataset.authMode)));
document.getElementById('auth-form').addEventListener('submit',async event=>{const formElement=event.currentTarget;event.preventDefault();const form=new FormData(formElement);const payload={email:form.get('email'),password:form.get('password')};if(authMode==='register'){payload.name=form.get('name');payload.account_type=form.get('account_type')}try{const result=await api(`/api/auth/${authMode==='register'?'register':'login'}`,{method:'POST',body:JSON.stringify(payload)});formElement.reset();showWorkspace(result.user)}catch(error){if(authMode==='register'&&error.message.includes('already registered')){const email=document.getElementById('auth-email').value;setAuthMode('login');document.getElementById('auth-email').value=email;document.getElementById('auth-error').textContent='This email already has an account. Sign in with it, or use another email to register.';return}document.getElementById('auth-error').textContent=error.message}});
document.getElementById('sign-out').addEventListener('click',async()=>{if(state.locationWatchId!==null)navigator.geolocation.clearWatch(state.locationWatchId);if(state.userRole==='rescuer'&&state.locationSharing){try{await api('/api/responder/location',{method:'DELETE'})}catch{}}state.locationWatchId=null;state.locationSharing=false;authenticated=false;if(state.socket)state.socket.close();try{await api('/api/auth/logout',{method:'POST'})}catch{}document.querySelector('.shell').hidden=true;document.getElementById('auth-screen').hidden=false;document.getElementById('account-name').textContent='';setAuthMode('login')});
document.querySelectorAll('[data-view]').forEach(link=>link.addEventListener('click',event=>{event.preventDefault();setView(link.dataset.view)}));document.querySelectorAll('[data-view-link]').forEach(button=>button.addEventListener('click',()=>setView(button.dataset.viewLink)));
let modalReturnFocus=null;
function openModal(id){const modal=document.getElementById(id);if(!modal)return;modalReturnFocus=document.activeElement;modal.classList.add('open');document.body.classList.add('modal-open');const focusTarget=modal.querySelector('textarea,input,select,button');if(focusTarget)setTimeout(()=>focusTarget.focus(),40)}
function closeModal(modal){if(!modal)return;modal.classList.remove('open');document.body.classList.remove('modal-open');if(modalReturnFocus&&document.contains(modalReturnFocus))modalReturnFocus.focus();modalReturnFocus=null}
document.addEventListener('keydown',event=>{const open=document.querySelector('.modal-backdrop.open');if(!open)return;if(event.key==='Escape'){event.preventDefault();closeModal(open);return}if(event.key==='Tab'){const focusable=[...open.querySelectorAll('button,input,select,textarea,a[href]')].filter(element=>!element.disabled&&element.offsetParent!==null);if(!focusable.length)return;const first=focusable[0];const last=focusable[focusable.length-1];if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus()}else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus()}}});
document.querySelectorAll('[data-open-report]').forEach(button=>button.addEventListener('click',()=>openModal('report-modal')));document.querySelectorAll('[data-close-modal]').forEach(button=>button.addEventListener('click',()=>closeModal(button.closest('.modal-backdrop'))));document.querySelectorAll('.modal-backdrop').forEach(backdrop=>backdrop.addEventListener('click',event=>{if(event.target===backdrop)closeModal(backdrop)}));document.querySelectorAll('[data-geolocate]').forEach(button=>button.addEventListener('click',()=>geolocate(button.dataset.geolocate)));
document.getElementById('report-text').addEventListener('input',previewPriority);previewPriority();
const necessityOptions=['Medicine','Food','Water','Clothing','Blankets','First aid','Mobility support'];const needsPicker=document.createElement('div');needsPicker.className='field';needsPicker.innerHTML=`<label>What necessities are needed?</label><div class="needs-options">${necessityOptions.map(need=>`<label><input type="checkbox" name="needs" value="${need}"><span>${need}</span></label>`).join('')}</div><span class="field-hint">Select any medicine, food, water, or other essentials responders should bring.</span>`;document.getElementById('report-text').parentElement.after(needsPicker);
document.getElementById('report-form').addEventListener('submit',async event=>{const formElement=event.currentTarget;event.preventDefault();const form=new FormData(formElement);const payload={raw_report:form.get('raw_report'),user_lat:Number(form.get('user_lat')),user_lng:Number(form.get('user_lng')),needs:form.getAll('needs')};try{const created=await api('/api/incidents/report',{method:'POST',body:JSON.stringify(payload)});closeModal(document.getElementById('report-modal'));formElement.reset();previewPriority();await loadData();toastMessage(`Emergency report #${created.incident_id} recorded at ${created.severity} priority.`)}catch(error){toastMessage(error.message)}});
document.getElementById('team-form').addEventListener('submit',async event=>{const formElement=event.currentTarget;event.preventDefault();const form=new FormData(formElement);try{const payload={name:form.get('name'),contact:form.get('contact')||null,location_lat:Number(form.get('location_lat')),location_lng:Number(form.get('location_lng'))};const team=await api('/api/teams',{method:'POST',body:JSON.stringify(payload)});formElement.reset();await loadData();toastMessage(`${team.name} added with GPS coordinates.`)}catch(error){toastMessage(error.message)}});
document.getElementById('status-filter').addEventListener('change',async event=>{try{const suffix=event.target.value?`?status=${encodeURIComponent(event.target.value)}`:'';const incidents=await api(`/api/incidents${suffix}`);document.getElementById('all-incidents').innerHTML=incidentRows(incidents);refreshIcons()}catch(error){toastMessage(error.message)}});
document.addEventListener('change',async event=>{const target=event.target;if(target.matches('.status-change')){try{await api(`/api/incidents/${target.dataset.id}/status`,{method:'PATCH',body:JSON.stringify({status:target.value})});await loadData();toastMessage('Incident status updated.')}catch(error){toastMessage(error.message);await loadData()}}if(target.matches('.assign-team')){const teamId=target.value?Number(target.value):null;try{await api(`/api/incidents/${target.dataset.id}/assign`,{method:'PATCH',body:JSON.stringify({team_id:teamId})});await loadData();toastMessage(teamId?'Incident assigned to the selected team.':'Incident returned to the pending queue.')}catch(error){toastMessage(error.message);await loadData()}}if(target.matches('.team-status')){try{await api(`/api/teams/${target.dataset.id}`,{method:'PATCH',body:JSON.stringify({status:target.value})});await loadData();toastMessage('Team availability updated.')}catch(error){toastMessage(error.message);await loadData()}}});
async function openIncidentDetail(incidentId){try{const result=await api(`/api/incidents/${incidentId}/report`);const data=result.report;const needs=Array.isArray(data.needs)&&data.needs.length?data.needs.join(', '):'None listed';const created=new Date(data.created_at+'Z').toLocaleString();const coords=`${Number(data.location_lat).toFixed(5)}, ${Number(data.location_lng).toFixed(5)}`;const maps=`https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(coords)}`;document.getElementById('detail-title').textContent=`Incident #${data.incident_id}`;document.getElementById('detail-content').innerHTML=`<div class="detail-report">${escapeHtml(data.raw_report)}</div><dl class="detail-grid"><dt>Priority</dt><dd><span class="severity-pill ${severityClass(data.severity)}">${escapeHtml(data.severity)}</span></dd><dt>Status</dt><dd>${statusPill(data.status)}</dd><dt>Reported</dt><dd>${escapeHtml(created)}</dd><dt>Needs</dt><dd>${escapeHtml(needs)}</dd><dt>Response team</dt><dd>${escapeHtml(data.assigned_team||'Unassigned')}${data.team_contact?` / ${escapeHtml(data.team_contact)}`:''}</dd><dt>Arrival</dt><dd>${routeArrival(data)}</dd><dt>Shelter</dt><dd>${shelterGuidance(data)}</dd><dt>Location</dt><dd class="mono">${escapeHtml(coords)}</dd></dl><div class="detail-actions"><a class="secondary" href="${maps}" target="_blank" rel="noopener">Open in Maps</a><button type="button" class="secondary" data-detail-close>Close</button></div>`;document.querySelectorAll('[data-detail-close]').forEach(button=>button.addEventListener('click',()=>closeModal(document.getElementById('detail-modal'))));refreshIcons();openModal('detail-modal')}catch(error){toastMessage(error.message)}}
document.addEventListener('click',async event=>{const remove=event.target.closest('.delete-team');if(remove&&confirm('Remove this team from the roster?')){try{await api(`/api/teams/${remove.dataset.id}`,{method:'DELETE'});await loadData();toastMessage('Team removed.')}catch(error){toastMessage(error.message)}}const report=event.target.closest('.download-report,.view-incident');if(report)openIncidentDetail(report.dataset.id)});
document.addEventListener('change',async event=>{const target=event.target;if(!target.matches('.responder-team'))return;const responderId=Number(target.dataset.userId);const currentTeam=state.teams.find(team=>team.responder_user_id===responderId);const selectedTeamId=target.value?Number(target.value):null;const teamId=selectedTeamId||(currentTeam&&currentTeam.team_id);if(!teamId)return;try{await api(`/api/teams/${teamId}`,{method:'PATCH',body:JSON.stringify({responder_user_id:selectedTeamId?responderId:null})});await loadData();toastMessage(selectedTeamId?'Responder linked to the rescue team.':'Responder unlinked from the rescue team.')}catch(error){toastMessage(error.message);await loadData()}});
document.getElementById('shelter-form').addEventListener('submit',async event=>{const formElement=event.currentTarget;event.preventDefault();const form=new FormData(formElement);const payload={name:form.get('name'),address:form.get('address'),contact:form.get('contact')||null,location_lat:Number(form.get('location_lat')),location_lng:Number(form.get('location_lng'))};try{const shelter=await api('/api/shelters',{method:'POST',body:JSON.stringify(payload)});formElement.reset();await loadData();toastMessage(`${shelter.name} added to the shelter directory.`)}catch(error){toastMessage(error.message)}});
document.addEventListener('change',async event=>{const target=event.target;if(!target.matches('.shelter-status'))return;try{await api(`/api/shelters/${target.dataset.id}`,{method:'PATCH',body:JSON.stringify({status:target.value})});await loadData();toastMessage('Shelter availability updated.')}catch(error){toastMessage(error.message);await loadData()}});
document.addEventListener('click',async event=>{const shelter=event.target.closest('.delete-shelter');if(shelter&&confirm('Remove this shelter from future recommendations?')){try{await api(`/api/shelters/${shelter.dataset.id}`,{method:'DELETE'});await loadData();toastMessage('Shelter removed.')}catch(error){toastMessage(error.message)}}});
document.getElementById('location-sharing-toggle').addEventListener('click',()=>{if(state.locationSharing)stopResponderLocationShare();else startResponderLocationShare()});
function updateClock(){document.getElementById('clock').textContent=new Date().toLocaleString(undefined,{weekday:'short',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'})}updateClock();setInterval(updateClock,30000);restoreSession();refreshIcons();
</script>
</body>
</html>"""
