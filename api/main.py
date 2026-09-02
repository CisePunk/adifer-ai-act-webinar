import os, csv, io, json, secrets
import psycopg
from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials

DB_URL  = os.environ["DATABASE_URL"]
ORIGIN  = os.environ["ALLOWED_ORIGIN"]
ADMIN_U = os.environ.get("ADMIN_USER", "adifer")
ADMIN_P = os.environ["ADMIN_PASS"]

app = FastAPI(title="ADIFER check API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[ORIGIN],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


def db():
    return psycopg.connect(DB_URL)


@app.on_event("startup")
def init():
    with db() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS submissions(
                id BIGSERIAL PRIMARY KEY,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                nome TEXT, azienda TEXT, email TEXT, telefono TEXT,
                settore TEXT, dimensione TEXT, ruolo TEXT,
                consenso BOOLEAN NOT NULL,
                answers JSONB, report JSONB, user_agent TEXT)"""
        )


@app.get("/")
def health():
    return {"status": "ok"}


@app.post("/submit")
async def submit(req: Request):
    d = await req.json()
    if d.get("website"):                       # honeypot: bot filled a hidden field
        return {"ok": True}
    if not d.get("consenso"):
        raise HTTPException(400, "Consenso mancante")
    if not (d.get("nome") or "").strip() or not (d.get("email") or "").strip():
        raise HTTPException(400, "Nome ed email obbligatori")
    with db() as c:
        c.execute(
            """INSERT INTO submissions
               (nome,azienda,email,telefono,settore,dimensione,ruolo,consenso,answers,report,user_agent)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                d.get("nome"), d.get("azienda"), d.get("email"), d.get("telefono"),
                d.get("settore"), d.get("dimensione"), d.get("ruolo"), True,
                json.dumps(d.get("answers")), json.dumps(d.get("report")),
                req.headers.get("user-agent"),
            ),
        )
    return {"ok": True}


_sec = HTTPBasic()


def _admin(cr: HTTPBasicCredentials = Depends(_sec)):
    ok = secrets.compare_digest(cr.username, ADMIN_U) and secrets.compare_digest(cr.password, ADMIN_P)
    if not ok:
        raise HTTPException(401, headers={"WWW-Authenticate": "Basic"})


@app.get("/admin/export.csv", dependencies=[Depends(_admin)])
def export():
    cols = ["id", "created_at", "nome", "azienda", "email", "telefono",
            "settore", "dimensione", "ruolo", "consenso", "answers", "report"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    with db() as c:
        for row in c.execute(f"SELECT {','.join(cols)} FROM submissions ORDER BY id DESC"):
            w.writerow(row)
    return Response(
        buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=adifer-leads.csv"},
    )
