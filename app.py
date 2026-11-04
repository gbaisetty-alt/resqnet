import csv
import io
import os
from contextlib import closing
from typing import Literal, Optional

import psycopg2
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from psycopg2 import errorcodes

app = FastAPI(title="ResQNet API")


class TeamCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    contact: Optional[str] = None
    location_lat: Optional[float] = Field(default=None, ge=-90, le=90)
    location_lng: Optional[float] = Field(default=None, ge=-180, le=180)


class TeamUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    contact: Optional[str] = None
    status: Optional[Literal["Available", "Deployed", "Unavailable"]] = None
    location_lat: Optional[float] = Field(default=None, ge=-90, le=90)
    location_lng: Optional[float] = Field(default=None, ge=-180, le=180)


class IncidentStatusUpdate(BaseModel):
    status: Literal["Pending", "Assigned", "EnRoute", "OnScene", "Resolved", "Cancelled"]


class IncidentAssignment(BaseModel):
    team_id: int = Field(gt=0)


class IncidentUpdates:
    def __init__(self):
        self.connections = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.connections:
            self.connections.remove(websocket)

    async def broadcast(self, update):
        disconnected = []
        for websocket in self.connections:
            try:
                await websocket.send_json(update)
            except (WebSocketDisconnect, RuntimeError):
                disconnected.append(websocket)
        for websocket in disconnected:
            self.disconnect(websocket)


incident_updates = IncidentUpdates()


def get_db_connection():
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise HTTPException(
            status_code=503,
            detail="Database is not configured. Set the DATABASE_URL environment variable.",
        )
    return psycopg2.connect(database_url)


def row_as_dict(cursor, row):
    return dict(zip((column.name for column in cursor.description), row))


@app.on_event("startup")
def initialize_database():
    if not os.getenv("DATABASE_URL"):
        return

    with closing(get_db_connection()) as conn:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS rescue_teams (
                        team_id SERIAL PRIMARY KEY,
                        name TEXT NOT NULL UNIQUE,
                        contact TEXT,
                        location_lat DOUBLE PRECISION,
                        location_lng DOUBLE PRECISION,
                        status TEXT NOT NULL DEFAULT 'Available'
                    );
                    CREATE TABLE IF NOT EXISTS incidents (
                        incident_id SERIAL PRIMARY KEY,
                        raw_report TEXT NOT NULL,
                        parsed_keywords TEXT,
                        severity TEXT NOT NULL DEFAULT 'High',
                        status TEXT NOT NULL DEFAULT 'Pending',
                        location_lat DOUBLE PRECISION NOT NULL,
                        location_lng DOUBLE PRECISION NOT NULL,
                        assigned_team_id INTEGER REFERENCES rescue_teams(team_id) ON DELETE SET NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    ALTER TABLE incidents
                    ADD COLUMN IF NOT EXISTS assigned_team_id INTEGER
                    REFERENCES rescue_teams(team_id) ON DELETE SET NULL;
                    ALTER TABLE incidents
                    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
                    """
                )


@app.exception_handler(psycopg2.Error)
async def handle_database_error(_, exc):
    if exc.pgcode == errorcodes.UNIQUE_VIOLATION:
        return JSONResponse(status_code=409, content={"detail": "A record with that value already exists."})
    if exc.pgcode == errorcodes.FOREIGN_KEY_VIOLATION:
        return JSONResponse(status_code=404, content={"detail": "The referenced record was not found."})
    return JSONResponse(status_code=503, content={"detail": "The database could not complete the request."})


@app.post("/incidents/report", status_code=201)
def create_dynamic_incident(
    raw_report: str = Query(..., min_length=1),
    user_lat: float = Query(..., ge=-90, le=90),
    user_lng: float = Query(..., ge=-180, le=180),
):
    detected_keywords = "Fire, Trapped"
    assessed_severity = "High"
    with closing(get_db_connection()) as conn:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO incidents (
                        raw_report, parsed_keywords, severity, status, location_lat, location_lng
                    )
                    VALUES (%s, %s, %s, 'Pending', %s, %s)
                    RETURNING incident_id, raw_report, parsed_keywords, severity, status,
                              location_lat, location_lng, assigned_team_id, created_at;
                    """,
                    (raw_report, detected_keywords, assessed_severity, user_lat, user_lng),
                )
                report = row_as_dict(cursor, cursor.fetchone())
    return report


@app.get("/teams")
def list_teams():
    with closing(get_db_connection()) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM rescue_teams ORDER BY name;")
            return [row_as_dict(cursor, row) for row in cursor.fetchall()]


@app.post("/teams", status_code=201)
def create_team(team: TeamCreate):
    with closing(get_db_connection()) as conn:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO rescue_teams (name, contact, location_lat, location_lng)
                    VALUES (%s, %s, %s, %s)
                    RETURNING *;
                    """,
                    (team.name, team.contact, team.location_lat, team.location_lng),
                )
                return row_as_dict(cursor, cursor.fetchone())


@app.patch("/teams/{team_id}")
def update_team(team_id: int, update: TeamUpdate):
    changes = update.dict(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="Provide at least one field to update.")
    set_clause = ", ".join(f"{field} = %s" for field in changes)
    with closing(get_db_connection()) as conn:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    f"UPDATE rescue_teams SET {set_clause} WHERE team_id = %s RETURNING *;",
                    (*changes.values(), team_id),
                )
                row = cursor.fetchone()
                if row is None:
                    raise HTTPException(status_code=404, detail="Rescue team not found.")
                result = row_as_dict(cursor, row)
    return result


@app.delete("/teams/{team_id}", status_code=204)
def delete_team(team_id: int):
    with closing(get_db_connection()) as conn:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM rescue_teams WHERE team_id = %s;", (team_id,))
                if cursor.rowcount == 0:
                    raise HTTPException(status_code=404, detail="Rescue team not found.")


@app.get("/incidents")
def list_incidents():
    with closing(get_db_connection()) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM incidents ORDER BY created_at DESC;")
            return [row_as_dict(cursor, row) for row in cursor.fetchall()]


@app.patch("/incidents/{incident_id}/status")
def update_incident_status(
    incident_id: int,
    update: IncidentStatusUpdate,
    background_tasks: BackgroundTasks,
):
    with closing(get_db_connection()) as conn:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE incidents SET status = %s
                    WHERE incident_id = %s
                    RETURNING incident_id, status, assigned_team_id;
                    """,
                    (update.status, incident_id),
                )
                row = cursor.fetchone()
                if row is None:
                    raise HTTPException(status_code=404, detail="Incident not found.")
                result = row_as_dict(cursor, row)
    background_tasks.add_task(incident_updates.broadcast, {"type": "status.updated", **result})
    return result


@app.post("/incidents/{incident_id}/assign")
def assign_incident(
    incident_id: int,
    assignment: IncidentAssignment,
    background_tasks: BackgroundTasks,
):
    with closing(get_db_connection()) as conn:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT team_id FROM rescue_teams WHERE team_id = %s;",
                    (assignment.team_id,),
                )
                if cursor.fetchone() is None:
                    raise HTTPException(status_code=404, detail="Rescue team not found.")
                cursor.execute(
                    """
                    UPDATE incidents SET assigned_team_id = %s, status = 'Assigned'
                    WHERE incident_id = %s
                    RETURNING incident_id, status, assigned_team_id;
                    """,
                    (assignment.team_id, incident_id),
                )
                row = cursor.fetchone()
                if row is None:
                    raise HTTPException(status_code=404, detail="Incident not found.")
                result = row_as_dict(cursor, row)
                cursor.execute(
                    "UPDATE rescue_teams SET status = 'Deployed' WHERE team_id = %s;",
                    (assignment.team_id,),
                )
    background_tasks.add_task(incident_updates.broadcast, {"type": "team.assigned", **result})
    return result


@app.get("/incidents/{incident_id}/report")
def generate_incident_report(incident_id: int):
    with closing(get_db_connection()) as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT i.incident_id, i.raw_report, i.parsed_keywords, i.severity, i.status,
                       i.location_lat, i.location_lng, i.assigned_team_id, i.created_at,
                       t.name AS assigned_team, t.contact AS team_contact
                FROM incidents AS i
                LEFT JOIN rescue_teams AS t ON t.team_id = i.assigned_team_id
                WHERE i.incident_id = %s;
                """,
                (incident_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Incident not found.")
            return row_as_dict(cursor, row)


@app.get("/reports/incidents.csv")
def export_incident_reports():
    with closing(get_db_connection()) as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT i.incident_id, i.raw_report, i.parsed_keywords, i.severity, i.status,
                       i.location_lat, i.location_lng, i.assigned_team_id, i.created_at,
                       t.name AS assigned_team
                FROM incidents AS i
                LEFT JOIN rescue_teams AS t ON t.team_id = i.assigned_team_id
                ORDER BY i.created_at DESC;
                """
            )
            rows = cursor.fetchall()
            headers = [column.name for column in cursor.description]
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    writer.writerows(rows)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=emergency-reports.csv"},
    )


@app.websocket("/ws/incidents")
async def stream_incident_updates(websocket: WebSocket):
    await incident_updates.connect(websocket)
    try:
        await websocket.send_json({"type": "connected"})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        incident_updates.disconnect(websocket)