from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Float
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime

DATABASE_URL = "sqlite:///./enterprise_secure.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class BankRecord(Base):
    __tablename__ = "bank_records"

    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(String, nullable=False)
    customer_name = Column(String, nullable=False)
    account_number = Column(String, nullable=False)
    bank_name = Column(String, nullable=False)
    branch = Column(String, nullable=False)
    city = Column(String, nullable=False)
    balance = Column(String, nullable=False)

    tokens = relationship("SearchToken", back_populates="record", cascade="all, delete-orphan")

class SearchToken(Base):
    __tablename__ = "search_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, index=True)
    record_id = Column(Integer, ForeignKey("bank_records.id"))

    record = relationship("BankRecord", back_populates="tokens")

# MODULE 1: Blockchain Chain
class BlockchainBlock(Base):
    __tablename__ = "blockchain_chain"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action = Column(String)
    user = Column(String)
    previous_hash = Column(String)
    current_hash = Column(String)

# MODULE 2: Audit Logs
class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user = Column(String)
    action = Column(String)
    details = Column(String)
    hash = Column(String) # For integrity

# MODULE 3: Anomaly Monitoring
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
    if not db.query(User).filter(User.username == "admin").first():
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        admin = User(username="admin", hashed_password=pwd_context.hash("admin123"))
        db.add(admin)
        db.commit()
    db.close()

if __name__ == "__main__":
    init_db()