# app.py
import os
from datetime import datetime, timedelta
from typing import List
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, ForeignKey, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import jwt
from pydantic import BaseModel

# === الإعدادات ===
SECRET_KEY = os.getenv("SECRET_KEY", "instaboost_secret_key_123!")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DATABASE_URL = "sqlite:///./instaboost.db"

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
    amount_usd = Column(String)  # يمكن تغييره إلى Float لاحقًا
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

# إنشاء الجداول
Base.metadata.create_all(bind=engine)

# === التشفير والمصادقة ===
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# === Pydantic Schemas (متوافق مع V2) ===
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
        from_attributes = True

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
        from_attributes = True

class ReviewCreate(BaseModel):
    rating: int
    comment: str

class ReviewOut(BaseModel):
    id: int
    user_id: int
    rating: int
    comment: str
    class Config:
        from_attributes = True

# === FastAPI App ===
app = FastAPI(title="InstaBoost API - All in One")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === قاعدة بيانات Dependency ===
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

@app.post("/api/orders/free-trial", response_model=OrderOut)
def free_trial(instagram_target: str, db: Session = Depends(get_db)):
    user = db.query(User).first()
    if not user:
        raise HTTPException(400, "No users found. Register first.")
    order = Order(
        user_id=user.id,
        service_type="followers_likes",
        quantity=20,
        amount_usd="0.00",
        instagram_target=instagram_target,
        status="pending"
    )
    db.add(order)
    db.commit()
    db.refresh(order)
    return order

@app.post("/api/orders/paid", response_model=OrderOut)
def paid_order(order: OrderCreate, db: Session = Depends(get_db)):
    user = db.query(User).first()
    if not user:
        raise HTTPException(400, "No users found.")
    # تحقق من السعر
    if order.service_type == "followers" and order.quantity >= 100:
        expected = f"{order.quantity / 100 * 0.2:.2f}"
    elif order.service_type == "likes" and order.quantity >= 100:
        expected = f"{order.quantity / 100 * 0.1:.2f}"
    else:
        raise HTTPException(400, "Invalid quantity or service")
    if order.amount_usd != expected:
        raise HTTPException(400, "Price mismatch")
    new_order = Order(
        user_id=user.id,
        service_type=order.service_type,
        quantity=order.quantity,
        amount_usd=order.amount_usd,
        instagram_target=order.instagram_target,
        status="pending"
    )
    db.add(new_order)
    db.commit()
    db.refresh(new_order)
    return new_order

@app.post("/api/reviews", response_model=ReviewOut)
def create_review(review: ReviewCreate, db: Session = Depends(get_db)):
    user = db.query(User).first()
    if not user:
        raise HTTPException(400, "No users found.")
    if not (1 <= review.rating <= 5):
        raise HTTPException(400, "Rating must be 1-5")
    r = Review(user_id=user.id, rating=review.rating, comment=review.comment)
    db.add(r)
    db.commit()
    db.refresh(r)
    return r

@app.get("/api/reviews", response_model=List[ReviewOut])
def get_reviews(db: Session = Depends(get_db)):
    return db.query(Review).all()

# === لوحة التحكم (Admin) ===
@app.get("/api/admin/dashboard")
def dashboard(db: Session = Depends(get_db)):
    return {
        "total_users": db.query(User).count(),
        "total_orders": db.query(Order).count(),
        "total_reviews": db.query(Review).count(),
        "revenue": sum([float(o.amount_usd) for o in db.query(Order).all()])
    }

@app.get("/api/admin/users", response_model=List[UserOut])
def admin_users(db: Session = Depends(get_db)):
    return db.query(User).all()

@app.get("/api/admin/orders", response_model=List[OrderOut])
def admin_orders(db: Session = Depends(get_db)):
    return db.query(Order).all()

# === WebSocket للدردشة ===
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

manager = ConnectionManager()

@app.websocket("/api/chat/support")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        await manager.send_personal_message("مرحباً! كيف يمكنني مساعدتك اليوم؟", websocket)
        while True:
            data = await websocket.receive_text()
            await manager.send_personal_message("شكراً لرسالتك! سنتواصل معك قريباً.", websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# === الصفحة الجذر ===
@app.get("/")
def root():
    return {"message": "InstaBoost API - All in One is running!"}
