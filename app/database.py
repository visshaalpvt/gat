from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Float
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime

DATABASE_URL = "sqlite:///./enterprise_secure_v2.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30}
)

SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String) # Super Admin, Security Analyst, Auditor, Bank Officer

class BankRecord(Base):
    __tablename__ = "bank_records"

    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(String, unique=True, nullable=False)
    full_name = Column(String, nullable=False)
    account_number = Column(String, unique=True, nullable=False)
    phone_number = Column(String, nullable=False)
    ifsc_code = Column(String, nullable=False)
    branch = Column(String, nullable=False)
    city = Column(String, nullable=False)
    balance = Column(String, nullable=False)
    risk_score = Column(String, nullable=True)
    kyc_id = Column(String, nullable=True)
    device_id = Column(String, nullable=True)
    last_transaction_amount = Column(String, nullable=True)
    last_login_location = Column(String, nullable=True)

    tokens = relationship("SearchToken", back_populates="record", cascade="all, delete-orphan")

class SearchToken(Base):
    __tablename__ = "search_tokens"
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, index=True)
    field = Column(String) # name, phone, account, ifsc, city, kyc
    record_id = Column(Integer, ForeignKey("bank_records.id"))
    record = relationship("BankRecord", back_populates="tokens")

class BlockchainBlock(Base):
    __tablename__ = "blockchain_chain"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action = Column(String)
    user = Column(String)
    previous_hash = Column(String)
    current_hash = Column(String)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user = Column(String)
    action = Column(String)
    mode = Column(String, nullable=True)
    details = Column(String)
    hash = Column(String)

class UserActivity(Base):
    __tablename__ = "user_activity"
    id = Column(Integer, primary_key=True, index=True)
    user = Column(String, index=True)
    search_count = Column(Integer, default=0)
    last_action_time = Column(DateTime, default=datetime.utcnow)
    risk_score = Column(Float, default=0.0)

def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    roles = {
        "admin": "Super Admin",
        "analyst": "Security Analyst",
        "auditor": "Auditor",
        "officer": "Bank Officer"
    }
    
    for username, role in roles.items():
        if not db.query(User).filter(User.username == username).first():
            new_user = User(
                username=username, 
                hashed_password=pwd_context.hash(f"{username}123"),
                role=role
            )
            db.add(new_user)
    
    db.commit()
    db.close()

if __name__ == "__main__":
    init_db()