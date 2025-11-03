import os
from datetime import datetime, timedelta
from typing import List
from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, ForeignKey, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel

# === الإعدادات ===
SECRET_KEY = os.getenv("SECRET_KEY", "instaboost_secret_key_123!")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/instaboost.db")

# === قاعدة البيانات ===
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# === النماذج ===
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    service_type = Column(String)
    quantity = Column(Integer)
    amount_usd = Column(String)
    status = Column(String, default="pending")
    instagram_target = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Review(Base):
    __tablename__ = "reviews"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    rating = Column(Integer)
    comment = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

Base.metadata.create_all(bind=engine)

# === التشفير والمصادقة ===
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# === Pydantic Schemas ===
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class OrderCreate(BaseModel):
    service_type: str
    quantity: int
    amount_usd: str
    instagram_target: str

class OrderOut(BaseModel):
    id: int
    service_type: str
    quantity: int
    amount_usd: str
    status: str
    class Config:
        orm_mode = True

class ReviewCreate(BaseModel):
    rating: int
    comment: str

class ReviewOut(BaseModel):
    id: int
    user_id: int
    rating: int
    comment: str
    class Config:
        orm_mode = True

# === FastAPI App ===
app = FastAPI(title="InstaBoost API - All in One")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# === مصادقة المستخدم ===
def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

# === Endpoints ===
@app.post("/api/auth/register", response_model=UserOut)
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(400, "Username already registered")
    hashed = get_password_hash(user.password)
    new_user = User(username=user.username, email=user.email, hashed_password=hashed)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/api/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(401, "Invalid credentials")
    token = create_access_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

# باقي Endpoints (Orders, Reviews, Admin, WebSocket) تبقى كما هي مع نفس الكود السابق
# يمكنك إضافتها مباشرة من النسخة التي لديك

@app.get("/")
def root():
    return {"message": "InstaBoost API - All in One is running!"}
