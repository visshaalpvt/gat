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
import random

from app.database import (SessionLocal, BankRecord, SearchToken, init_db,
                           AuditLog, BlockchainBlock, UserActivity, User)
from app.crypto import (encrypt, decrypt_server, generate_search_token,
                         generate_prefixes, calculate_block_hash)
from app.auth import create_access_token, get_current_user, verify_password, get_db, ACCESS_TOKEN_EXPIRE_MINUTES

app = FastAPI(title="CipherProxy — Enterprise Privacy Engine")
init_db()

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

# ===== ROLE-BASED VISIBILITY ENGINE =====
def apply_rbac(record: BankRecord, role: str):
    """Mask data based on enterprise role"""
    # Note: Decryption happens here on the server only for the authenticated role's view
    def dec(field): return decrypt_server(field)
    def mask(val, visible_chars=4): 
        s = dec(val)
        return s[:visible_chars] + "*" * (len(s) - visible_chars) if len(s) > visible_chars else "****"

    data = {
        "id": record.id,
        "customer_id": mask(record.customer_id) if role != "Super Admin" else dec(record.customer_id),
        "full_name": dec(record.full_name) if role in ["Super Admin", "Bank Officer"] else mask(record.full_name),
        "city": dec(record.city),
        "branch": dec(record.branch),
        "risk_score": dec(record.risk_score),
    }

    if role == "Super Admin":
        data.update({
            "account_number": dec(record.account_number),
            "phone_number": dec(record.phone_number),
            "ifsc": dec(record.ifsc_code),
            "balance": dec(record.balance),
            "kyc_id": dec(record.kyc_id),
            "device_id": dec(record.device_id)
        })
    elif role == "Security Analyst":
        data.update({
            "account_number": mask(record.account_number),
            "phone_number": mask(record.phone_number),
            "ifsc": dec(record.ifsc_code),
            "balance": "[HIDDEN]",
            "kyc_id": dec(record.kyc_id),
            "device_id": dec(record.device_id)
        })
    elif role == "Auditor":
        data.update({
            "account_number": mask(record.account_number),
            "phone_number": "[PROTECTED]",
            "ifsc": dec(record.ifsc_code),
            "balance": mask(record.balance, 2),
            "kyc_id": mask(record.kyc_id),
            "device_id": "[PROTECTED]"
        })
    else: # Bank Officer
        data.update({
            "account_number": mask(record.account_number),
            "phone_number": mask(record.phone_number, 4),
            "ifsc": mask(record.ifsc_code, 4),
            "balance": dec(record.balance),
            "kyc_id": "[HIDDEN]",
            "device_id": "[HIDDEN]"
        })
    
    # Ensure name is also masked for non-privileged roles if requested
    if role not in ["Super Admin", "Bank Officer"]:
        data["full_name"] = mask(record.full_name, 2)
    
    return data

# ===== BLOCKCHAIN HELPER =====
def add_block(db: Session, user: str, action: str, details: str, mode: str = "UNIFIED"):
    log = AuditLog(user=user, action=action, details=details, mode=mode,
                   hash=hashlib.sha256(f"{action}{details}{user}{mode}".encode()).hexdigest())
    db.add(log)

    last = db.query(BlockchainBlock).order_by(BlockchainBlock.id.desc()).first()
    prev_hash = last.current_hash if last else "GENESIS_" + "0" * 56
    ts = datetime.utcnow()
    curr_hash = calculate_block_hash(prev_hash, action, ts, user)
    db.add(BlockchainBlock(action=action, user=user, timestamp=ts,
                           previous_hash=prev_hash, current_hash=curr_hash))

    act = db.query(UserActivity).filter(UserActivity.user == user).first()
    if not act:
        act = UserActivity(user=user)
        db.add(act)

    if action == "SEARCH":
        act.search_count += 1
        
        # Rapid Search Burst Detection (Insiders scraping data)
        time_diff = (ts - act.last_burst_time).total_seconds()
        if time_diff < 2.0: # Searches less than 2 seconds apart
            act.burst_count += 1
            if act.burst_count > 5:
                act.risk_score = min(100, act.risk_score + 15)
                action = "RAPID_SEARCH_DETECTION"
                details = f"Anomaly: {act.burst_count} searches in < 10s. Scraping suspected."
        else:
            act.burst_count = 0
            act.last_burst_time = ts

        if act.search_count > 50: act.risk_score = min(100, act.risk_score + 5)
        elif act.search_count > 20: act.risk_score = min(100, act.risk_score + 2)
        
    elif action == "TRAPDOOR_TRIGGERED":
        act.risk_score = 100
        details = "CRITICAL: Insider attempting to access restricted cryptographic honeytokens."
        
    act.last_action_time = ts
    db.commit()

# ===== MAIL AUTOMATION ENGINE =====
def trigger_mail_automation(email: str, username: str, role: str):
    """Simulates enterprise mail automation when user logs in via email"""
    print(f"AUTOMATION_TRIGGERED: Sending security session initialization to {email}")
    # In a real system, this would use SMTP or an API like SendGrid/SES
    # For now, we log the automation event
    time.sleep(1) # Simulation delay
    print(f"MAIL_SENT: Session initialized for {username} [{role}]")

# ===== API ENDPOINTS =====
@app.post("/login")
async def login(background_tasks: BackgroundTasks, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # Login with either username or email
    user = db.query(User).filter(
        (User.username == form_data.username) | (User.email == form_data.username)
    ).first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # If logged in via email, trigger the mail automation engine
    if form_data.username == user.email:
        background_tasks.add_task(trigger_mail_automation, user.email, user.username, user.role)
    
    token = create_access_token(
        data={"sub": user.username, "role": user.role}, 
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    add_block(db, user.username, "LOGIN", f"Identity verified via {'EMAIL' if form_data.username == user.email else 'USERNAME'}. Session started for Role: {user.role}")
    return {"access_token": token, "token_type": "bearer", "role": user.role, "user_display": user.full_name or user.username}

@app.get("/stats")
async def stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return {
        "total_records": db.query(BankRecord).count(),
        "total_tokens": db.query(SearchToken).count(),
        "total_blocks": db.query(BlockchainBlock).count(),
        "total_logs": db.query(AuditLog).count(),
    }

@app.post("/register")
async def register(full_name: str, email: str, username: str, password: str, db: Session = Depends(get_db)):
    # Check if user already exists
    existing = db.query(User).filter((User.username == username) | (User.email == email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username or Email already registered")
    
    from app.auth import get_password_hash
    new_user = User(
        username=username,
        email=email,
        full_name=full_name,
        hashed_password=get_password_hash(password),
        role="Bank Officer" # Default role for new signups
    )
    db.add(new_user)
    db.commit()
    return {"status": "success", "message": "Account created successfully"}

@app.post("/secure-search")
async def secure_search(query: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    t0 = time.time()
    
    # 🕵️ HONEYTOKEN SECURITY PARADIGM
    honeytokens = ["admin_root", "password_db", "master_key", "dump_all"]
    if query.lower().strip() in honeytokens:
        add_block(db, current_user.username, "TRAPDOOR_TRIGGERED", f"CRITICAL: Accessing forbidden honeytoken: {query}")
        raise HTTPException(status_code=403, detail="SECURITY BREACH: AUTHORIZATION REVOKED.")

    clean_q = query.lower().strip()
    query_tokens = [generate_search_token(clean_q)]
    
    # Enable phonetic search for name queries (Auto-detected if query doesn't look like number)
    if not any(c.isdigit() for c in clean_q) and " " not in clean_q:
        from app.crypto import phonetic_encode
        soundex = phonetic_encode(clean_q)
        query_tokens.append(generate_search_token("PHONETIC_" + soundex))

    # Search across multi-field indices
    matches = db.query(SearchToken).filter(SearchToken.token.in_(query_tokens)).limit(100).all()

    results = []
    seen = set()
    for m in matches:
        if m.record_id not in seen:
            res_data = apply_rbac(m.record, current_user.role)
            res_data["match_type"] = "PHONETIC" if "PHONETIC_" in m.token else "EXACT"
            results.append(res_data)
            seen.add(m.record_id)

    elapsed = round((time.time() - t0) * 1000, 3)
    add_block(db, current_user.username, "SEARCH", f"Query: '{query}' | Results: {len(results)}")
    
    return {"results": results, "time_ms": elapsed, "count": len(results)}

@app.get("/tamper-check")
async def tamper_check(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    blocks = db.query(BlockchainBlock).order_by(BlockchainBlock.id).all()
    prev = "GENESIS_" + "0" * 56
    for b in blocks:
        if b.previous_hash != prev:
            return {"status": "TAMPERED", "block_id": b.id}
        prev = b.current_hash
    return {"status": "VERIFIED", "total": len(blocks)}

@app.get("/blockchain-chain")
async def get_chain(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    blocks = db.query(BlockchainBlock).order_by(BlockchainBlock.id.desc()).limit(50).all()
    return [{"id": b.id, "time": str(b.timestamp)[:19], "action": b.action, "user": b.user, "hash": b.current_hash[:16] + "..."} for b in blocks]

@app.get("/audit-logs")
async def audit_logs(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(100).all()
    return [{"id": l.id, "time": str(l.timestamp)[:19], "user": l.user, "action": l.action, "hash": l.hash[:16] + "..."} for l in logs]

@app.get("/anomaly-report")
async def anomaly_report(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    activities = db.query(UserActivity).all()
    alerts = [f"ALERT: {a.user} high search frequency ({a.risk_score}%)" for a in activities if a.risk_score > 30]
    
    # Real-time Frequency Graph Data
    now = datetime.utcnow()
    timeline = []
    for i in range(12):
        t = now - timedelta(minutes=i)
        c = db.query(AuditLog).filter(AuditLog.action == "SEARCH", AuditLog.timestamp > t - timedelta(minutes=1), AuditLog.timestamp <= t).count()
        timeline.append({"label": t.strftime("%H:%M"), "count": c})
    timeline.reverse()
    
    return {"users": [{"user": a.user, "score": a.risk_score} for a in activities], "alerts": alerts, "timeline": timeline}

@app.get("/performance-metrics")
async def perf_metrics(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Simulating micro-benchmarks
    t0 = time.time()
    for _ in range(50): encrypt("enterprise_banking_test")
    enc_time = round((time.time() - t0) / 50 * 1000, 3)
    
    t1 = time.time()
    for _ in range(50): generate_search_token("search_field_benchmark")
    tok_time = round((time.time() - t1) / 50 * 1000, 3)

    # Historical metrics for graph with more variations
    perf_history = []
    now = datetime.utcnow()
    for i in range(12):
        ts = now - timedelta(seconds=i*15)
        perf_history.append({
            "time": ts.strftime("%H:%M:%S"), 
            "enc": round(enc_time + random.uniform(-0.05, 0.05), 3), 
            "tok": round(tok_time + random.uniform(-0.05, 0.05), 3)
        })
    perf_history.reverse()

    return {
        "enc_speed_ms": enc_time,
        "tok_speed_ms": tok_time,
        "total_records": db.query(BankRecord).count(),
        "throughput": round(1000 / (enc_time + tok_time + 0.001), 1),
        "history": perf_history
    }

@app.get("/breach-simulation")
async def breach(db: Session = Depends(get_db)):
    recs = db.query(BankRecord).limit(10).all()
    return {"dump": [{"id": r.id, "bin_payload": r.account_number[:32] + "..." + r.customer_id[10:42]} for r in recs]}

@app.get("/")
def index():
    return FileResponse(os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html"))