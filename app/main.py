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
    elif action == "TRAPDOOR_TRIGGERED":
        act.risk_score = 100
        
    act.last_action_time = ts
    db.commit()


# ===== AUTH =====
@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(),
                db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # For demo roles: admin=Admin, manager=Manager, any other=Clerk
    role = "Admin" if user.username == "admin" else "Manager" if "manager" in user.username else "Clerk"
    token = create_access_token(data={"sub": user.username, "role": role})
    add_block(db, user.username, "LOGIN", f"JWT authentication successful. Role: {role}")
    return {"access_token": token, "token_type": "bearer", "role": role}


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
    
    # --- FEATURE: HONEYTOKEN TRAPDOOR ---
    honeytokens = ["admin_root", "password_db", "master_key", "dump_all", "sql_inject"]
    if query.lower().strip() in honeytokens:
        add_block(db, current_user.username, "TRAPDOOR_TRIGGERED", 
                 f"CRITICAL: User tried to access forbidden honeytoken: {query}")
        raise HTTPException(status_code=403, detail="CRITICAL SECURITY BREACH DETECTED. AUTHORIZATION REVOKED.")

    # Generate all query variants (Exact + Phonetic)
    query_tokens = [generate_search_token(query.lower().strip())]
    if " " not in query.strip(): # For single names, allow phonetic
        from app.crypto import phonetic_encode
        soundex = phonetic_encode(query.strip())
        query_tokens.append(generate_search_token("FUZZY_" + soundex))

    # Match against any of the tokens
    matches = db.query(SearchToken).filter(SearchToken.token.in_(query_tokens)).limit(50).all()

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
              f"query='{query}' results={len(results)} time={elapsed}ms")
    return {"results": results, "time_ms": elapsed, "count": len(results)}



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
        if a.risk_score > 70:
            alerts.append(f"CRITICAL: User '{a.user}' risk score is {a.risk_score}%")
        elif a.risk_score > 30:
            alerts.append(f"WARNING: User '{a.user}' unusual activity (score {a.risk_score}%)")

    now = datetime.utcnow()
    timeline = []
    # Get search counts for the last 12 minutes for a smooth graph
    for i in range(12):
        t_end = now - timedelta(minutes=i)
        t_start = t_end - timedelta(minutes=1)
        c = db.query(AuditLog).filter(
            AuditLog.action == "SEARCH",
            AuditLog.timestamp >= t_start,
            AuditLog.timestamp < t_end
        ).count()
        timeline.append({"label": t_end.strftime("%H:%M"), "count": c})
    timeline.reverse()

    return {
        "users": [{"user": a.user, "searches": a.search_count,
                    "score": a.risk_score, "last": str(a.last_action_time)[:19]}
                   for a in activities],
        "alerts": alerts,
        "timeline": timeline,
        "risk_dist": [
            db.query(UserActivity).filter(UserActivity.risk_score < 30).count(),
            db.query(UserActivity).filter(UserActivity.risk_score >= 30, UserActivity.risk_score < 70).count(),
            db.query(UserActivity).filter(UserActivity.risk_score >= 70).count()
        ]
    }


# ===== PERFORMANCE METRICS =====
@app.get("/performace-metrics") # Matching common misspelling in some frontend hits
@app.get("/performance-metrics")
async def perf_metrics(db: Session = Depends(get_db),
                       current_user: User = Depends(get_current_user)):
    # 1. Encryption Benchmark
    t0 = time.time()
    for _ in range(50):
        encrypt("bench_string_123456789")
    enc_time = round((time.time() - t0) / 50 * 1000, 3)

    # 2. Token Generation Benchmark
    t0 = time.time()
    for _ in range(50):
        generate_search_token("bench_query")
    tok_time = round((time.time() - t0) / 50 * 1000, 3)

    total_rec = db.query(BankRecord).count()
    
    return {
        "enc_speed_ms": enc_time,
        "tok_speed_ms": tok_time,
        "total_records": total_rec,
        "throughput": round(1000 / max(enc_time + tok_time, 0.001), 1)
    }



# ===== OPTIMIZED CSV UPLOAD (BATCHING) =====
def process_csv_task(content: str, user: str):
    db = SessionLocal()
    try:
        reader = csv.DictReader(io.StringIO(content))
        batch_size = 500
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
            db.flush() # Get ID
            
            prefixes = generate_prefixes(row.get('customer_name', '')) + generate_prefixes(row.get('city', ''))
            for p in set(prefixes):
                db.add(SearchToken(token=p, record_id=rec.id))
            
            count += 1
            if count % batch_size == 0:
                db.commit()
                print(f"Batch committed: {count} records")
        
        db.commit()
        add_block(db, user, "CSV_UPLOAD_COMPLETE", f"Processed {count} records in background.")
    except Exception as e:
        print(f"ERROR LOADING CSV: {e}")
        db.rollback()
    finally:
        db.close()

@app.post("/upload-csv")
async def upload_csv(bg: BackgroundTasks, file: UploadFile = File(...),
                      current_user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    content = (await file.read()).decode('utf-8')
    add_block(db, current_user.username, "CSV_UPLOAD_START", f"File: {file.filename}")
    bg.add_task(process_csv_task, content, current_user.username)
    return {"message": "CSV ingestion started in background."}


# ===== BREACH SIMULATION =====
@app.get("/breach-simulation")
async def breach(db: Session = Depends(get_db)):
    recs = db.query(BankRecord).limit(15).all()
    return {"dump": [{"id": r.id, "name": r.customer_name[:40],
                      "acc": r.account_number[:40],
                      "city": r.city[:40]} for r in recs]}


# ===== SERVE FRONTEND =====
@app.get("/")
def index():
    return FileResponse(os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html"))