# HAL 4.0 — Secure Search Intelligence Platform 🛡️

**Secured String Matching using Searchable Encryption**

HAL 4.0 is an enterprise-grade prototype designed to solve the critical privacy challenge: **How do we search over sensitive data without ever decrypting it?**

Traditional systems expose plaintext data to the server memory and database during search operations. HAL 4.0 implements a **Zero-Plaintext** architecture where data remains encrypted at rest and during the search process.

## 🚀 Key Features

- **🔍 Searchable Encryption**: Custom implementation using AES-256-CBC for storage and HMAC-SHA256 Blind Indexing for search.
- **🔗 Blockchain Tamper Protection**: Every search, login, and data modification is recorded in an immutable hash-chain ledger.
- **🚨 Anomaly Detection**: Real-time monitoring of user behavior with automated risk scoring and scraping protection.
- **📊 Performance Scorecard**: Live benchmarking of encryption speeds and search throughput.
- **💀 Breach Simulation**: A "Red Team" view that proves an attacker with full database access gains zero usable information.

## 🛠️ Technology Stack

- **Backend**: Python (FastAPI, SQLAlchemy)
- **Cryptography**: PyCryptodome (AES-256, HMAC-SHA256)
- **Frontend**: Vanilla JS (ES5 compatible for stability), CSS3 (Premium Dark/Light mode), Chart.js
- **Database**: SQLite (Relational structure for encrypted indexing)

## 🏗️ Architecture

1. **Encryption Layer**: Sensitive fields are encrypted using random IVs.
2. **Search Layer**: Search tokens (blind indexes) are generated using HMAC-SHA256. These tokens allow the server to find matches without knowing the underlying data.
3. **Integrity Layer**: A centralized blockchain links all critical actions. If a single bit in the database is manually altered, the `tamper-check` will immediately detect the broken hash chain.
4. **Local Decryption**: The server only returns cyphertext. Final decryption happens only in the authenticated user's browser, ensuring true End-to-End privacy.

## 🚦 Getting Started

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Generate Demo Data (10,000 Records)
```bash
python generate_bank_records.py
```

### 3. Run the Server
```bash
python -m uvicorn app.main:app --reload
```

### 4. Access the Dashboard
Navigate to `http://127.0.0.1:8000`

**Credentials:**
- **Username**: `admin`
- **Password**: `admin123`

## 🏆 Hackathon Alignment
This project directly addresses the **Secured String Matching** problem statement by demonstrating a production-ready approach to searchable encryption that satisfies both security (Privacy) and speed (Performance).
