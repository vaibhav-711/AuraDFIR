from datetime import datetime

from sqlalchemy import (
    Boolean, Column, Date, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint,
)

from app.database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    totp_secret = Column(String(64), nullable=False)
    mfa_enabled = Column(Boolean, default=True, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)


class UserSession(Base):
    __tablename__ = "user_sessions"
    id = Column(Integer, primary_key=True)
    token = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    # "password" = password ok, waiting for TOTP; "full" = authenticated
    stage = Column(String(16), default="password", nullable=False)
    client_ip = Column(String(64), default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)


class Case(Base):
    __tablename__ = "cases"
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, default="")
    status = Column(String(16), default="open", nullable=False)      # open | closed
    severity = Column(String(16), default="medium", nullable=False)  # low|medium|high|critical
    created_by = Column(String(64), default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CaseNote(Base):
    __tablename__ = "case_notes"
    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    author = Column(String(64), default="")
    body = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class AbuseIPDBKey(Base):
    __tablename__ = "abuseipdb_keys"
    id = Column(Integer, primary_key=True)
    label = Column(String(100), nullable=False)
    api_key = Column(String(120), nullable=False)
    daily_limit = Column(Integer, default=1000, nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class KeyUsage(Base):
    __tablename__ = "abuseipdb_key_usage"
    __table_args__ = (UniqueConstraint("key_id", "usage_date", name="uq_key_day"),)
    id = Column(Integer, primary_key=True)
    key_id = Column(Integer, ForeignKey("abuseipdb_keys.id"), nullable=False, index=True)
    usage_date = Column(Date, nullable=False, index=True)
    count = Column(Integer, default=0, nullable=False)
    # set when the API returned 429 for this key today (limit hit early / shared key)
    exhausted = Column(Boolean, default=False, nullable=False)


class IPReputation(Base):
    __tablename__ = "ip_reputation"
    id = Column(Integer, primary_key=True)
    ip = Column(String(64), unique=True, nullable=False, index=True)
    abuse_score = Column(Integer, default=0)
    total_reports = Column(Integer, default=0)
    country = Column(String(8), default="")
    isp = Column(String(200), default="")
    usage_type = Column(String(100), default="")
    domain = Column(String(200), default="")
    is_tor = Column(Boolean, default=False)
    last_reported_at = Column(String(40), default="")
    raw = Column(Text, default="{}")
    checked_at = Column(DateTime, default=datetime.utcnow)
