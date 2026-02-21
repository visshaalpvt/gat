import csv
import io
import time
import hashlib
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
import os

from app.database import (SessionLocal, BankRecord, SearchToken, init_db,
                           AuditLog, BlockchainBlock, UserActivity)
from app.crypto import (encrypt, decrypt_server, generate_search_token,
                         generate_prefixes, calculate_block_hash)
from app.auth import create_access_token, get_current_user, verify_password, get_db, User

app = FastAPI(title="HAL 4.0 — Secure Search Intelligence")
init_db()

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])


# ===== BLOCKCHAIN HELPER =====
def add_block(db: Session, user: str, action: str, details: str):
    """Create audit log + blockchain block for every action"""
    # Audit log
    log = AuditLog(user=user, action=action, details=details,
                   hash=hashlib.sha256(f"{action}{details}{user}".encode()).hexdigest())
    db.add(log)

    # Blockchain block
    last = db.query(BlockchainBlock).order_by(BlockchainBlock.id.desc()).first()
    prev_hash = last.current_hash if last else "GENESIS_" + "0" * 56
    ts = datetime.utcnow()
    curr_hash = calculate_block_hash(prev_hash, action, ts, user)
    db.add(BlockchainBlock(action=action, user=user, timestamp=ts,
                           previous_hash=prev_hash, current_hash=curr_hash))

    # Activity tracker
    act = db.query(UserActivity).filter(UserActivity.user == user).first()
    if not act:
        act = UserActivity(user=user)
        db.add(act)

    if action == "SEARCH":
        act.search_count += 1
        if act.search_count > 50:
            act.risk_score = min(100, act.risk_score + 8)
        elif act.search_count > 20:
            act.risk_score = min(100, act.risk_score + 3)
    act.last_action_time = ts
    db.commit()


# ===== AUTH =====
@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(),
                db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(data={"sub": user.username})
    add_block(db, user.username, "LOGIN", "JWT authentication successful")
    return {"access_token": token, "token_type": "bearer"}


# ===== STATS =====
@app.get("/stats")
async def stats(db: Session = Depends(get_db),
                current_user: User = Depends(get_current_user)):
    return {
        "total_records": db.query(BankRecord).count(),
        "total_tokens": db.query(SearchToken).count(),
        "total_blocks": db.query(BlockchainBlock).count(),
        "total_logs": db.query(AuditLog).count(),
    }


# ===== SECURE SEARCH (THE CORE PS) =====
@app.post("/secure-search")
async def secure_search(query: str,
                         db: Session = Depends(get_db),
                         current_user: User = Depends(get_current_user)):
    t0 = time.time()
    token = generate_search_token(query)
    matches = db.query(SearchToken).filter(SearchToken.token == token).limit(50).all()

    results = []
    seen = set()
    for m in matches:
        if m.record_id not in seen:
            r = m.record
            results.append({
                "id": r.id,
                "customer_name": r.customer_name,
                "account": r.account_number,
                "city": r.city,
                "bank": r.bank_name,
                "branch": r.branch,
            })
            seen.add(m.record_id)

    elapsed = round((time.time() - t0) * 1000, 2)
    add_block(db, current_user.username, "SEARCH",
              f"query_token={token[:16]}... results={len(results)} time={elapsed}ms")
    return {"results": results, "token": token, "time_ms": elapsed, "count": len(results)}


# ===== BLOCKCHAIN — TAMPER CHECK =====
@app.get("/tamper-check")
async def tamper_check(db: Session = Depends(get_db),
                       current_user: User = Depends(get_current_user)):
    blocks = db.query(BlockchainBlock).order_by(BlockchainBlock.id.asc()).all()
    prev = "GENESIS_" + "0" * 56
    for b in blocks:
        expected = calculate_block_hash(prev, b.action, b.timestamp, b.user)
        if b.current_hash != expected:
            return {"status": "TAMPER_DETECTED", "block_id": b.id, "total": len(blocks)}
        prev = b.current_hash
    return {"status": "VERIFIED", "total": len(blocks), "last_hash": prev[:32] + "..."}


# ===== BLOCKCHAIN — GET CHAIN =====
@app.get("/blockchain-chain")
async def get_chain(db: Session = Depends(get_db),
                    current_user: User = Depends(get_current_user)):
    blocks = db.query(BlockchainBlock).order_by(BlockchainBlock.id.desc()).limit(50).all()
    return [{"id": b.id, "time": str(b.timestamp)[:19], "action": b.action,
             "user": b.user, "prev": b.previous_hash[:16] + "...",
             "hash": b.current_hash[:16] + "..."} for b in blocks]


# ===== AUDIT LOGS =====
@app.get("/audit-logs")
async def audit_logs(db: Session = Depends(get_db),
                     current_user: User = Depends(get_current_user)):
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(100).all()
    return [{"id": l.id, "time": str(l.timestamp)[:19], "user": l.user,
             "action": l.action, "details": l.details, "hash": l.hash[:16] + "..."}
            for l in logs]


# ===== ANOMALY DETECTION =====
@app.get("/anomaly-report")
async def anomaly_report(db: Session = Depends(get_db),
                          current_user: User = Depends(get_current_user)):
    activities = db.query(UserActivity).all()
    alerts = []
    for a in activities:
        level = "NORMAL"
        if a.risk_score > 70:
            level = "CRITICAL"
            alerts.append(f"User '{a.user}': Data scraping behavior (score {a.risk_score})")
        elif a.risk_score > 30:
            level = "WARNING"
            alerts.append(f"User '{a.user}': Unusual search frequency (score {a.risk_score})")

    # Search frequency timeline (last 10 minutes)
    now = datetime.utcnow()
    timeline = []
    for i in range(10):
        t = now - timedelta(minutes=9 - i)
        c = db.query(AuditLog).filter(
            AuditLog.action == "SEARCH",
            AuditLog.timestamp >= t - timedelta(minutes=1),
            AuditLog.timestamp < t
        ).count()
        timeline.append({"label": t.strftime("%H:%M"), "count": c})

    return {
        "users": [{"user": a.user, "searches": a.search_count,
                    "score": a.risk_score, "last": str(a.last_action_time)[:19]}
                   for a in activities],
        "alerts": alerts,
        "timeline": timeline
    }


# ===== PERFORMANCE METRICS =====
@app.get("/performance-metrics")
async def perf_metrics(db: Session = Depends(get_db),
                       current_user: User = Depends(get_current_user)):
    # Run a live encryption benchmark
    t0 = time.time()
    for _ in range(100):
        encrypt("benchmark-test-string-12345")
    enc_time = round((time.time() - t0) / 100 * 1000, 3)

    # Run a live search benchmark
    t0 = time.time()
    for _ in range(100):
        generate_search_token("benchmark")
    tok_time = round((time.time() - t0) / 100 * 1000, 3)

    total_rec = db.query(BankRecord).count()
    total_tok = db.query(SearchToken).count()

    return {
        "enc_speed_ms": enc_time,
        "token_speed_ms": tok_time,
        "total_records": total_rec,
        "total_tokens": total_tok,
        "tokens_per_record": round(total_tok / max(total_rec, 1), 1),
        "throughput_est": round(1000 / max(enc_time, 0.001)),
    }


# ===== CSV UPLOAD =====
def process_csv(content: str, user: str):
    db = SessionLocal()
    try:
        reader = csv.DictReader(io.StringIO(content))
        count = 0
        for row in reader:
            rec = BankRecord(
                customer_id=encrypt(row.get('customer_id', '')),
                customer_name=encrypt(row.get('customer_name', '')),
                account_number=encrypt(row.get('account_number', '')),
                bank_name=encrypt(row.get('bank_name', '')),
                branch=encrypt(row.get('branch', '')),
                city=encrypt(row.get('city', '')),
                balance=encrypt(row.get('balance', '0'))
            )
            db.add(rec)
            db.flush()
            for t in set(generate_prefixes(row.get('customer_name', '')) +
                         generate_prefixes(row.get('city', ''))):
                db.add(SearchToken(token=t, record_id=rec.id))
            count += 1
        db.commit()
        add_block(db, user, "CSV_UPLOAD", f"{count} records encrypted and indexed")
    except Exception as e:
        db.rollback()
    finally:
        db.close()


@app.post("/upload-csv")
async def upload_csv(bg: BackgroundTasks, file: UploadFile = File(...),
                     current_user: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    content = (await file.read()).decode('utf-8')
    add_block(db, current_user.username, "CSV_UPLOAD_START", file.filename)
    bg.add_task(process_csv, content, current_user.username)
    return {"message": "Processing started"}


# ===== BREACH SIMULATION =====
@app.get("/breach-simulation")
async def breach(db: Session = Depends(get_db)):
    recs = db.query(BankRecord).limit(15).all()
    return {"dump": [{"id": r.id, "name": r.customer_name[:40] + "...",
                      "acc": r.account_number[:40] + "...",
                      "city": r.city[:40] + "..."} for r in recs]}


# ===== SERVE FRONTEND =====
@app.get("/")
def index():
    return FileResponse(os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html"))