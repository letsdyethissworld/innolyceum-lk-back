from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, constr, conint, validator
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import sessionmaker, relationship, declarative_base, Session
import re
import os
import shutil
import uuid
import io
import zipfile
import asyncio
import openpyxl
import smtplib
from email.message import EmailMessage
from fastapi_mail import ConnectionConfig, MessageSchema, FastMail

SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_ME_TO_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7
conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME", "innolyceum.lk@gmail.com"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD", "oxtp isvq sfis anig"),
    MAIL_FROM=os.getenv("MAIL_FROM", "innolyceum.lk@gmail.com"),
    MAIL_PORT=int(os.getenv("MAIL_PORT", 587)),
    MAIL_SERVER=os.getenv("MAIL_SERVER", "smtp.gmail.com"),
    MAIL_STARTTLS=os.getenv("MAIL_STARTTLS", "True").lower() == "true",
    MAIL_SSL_TLS=os.getenv("MAIL_SSL_TLS", "False").lower() == "true",
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
)



STORAGE_DIR = os.path.abspath("./storage")
os.makedirs(STORAGE_DIR, exist_ok=True)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./enrollment.db")
engine = create_engine(DATABASE_URL, connect_args={
                       "check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

ALLOWED_EXTENSIONS = {"pdf", "jpg", "jpeg", "png", "doc", "docx"}
MAX_FILE_SIZE = 10 * 1024 * 1024

app = FastAPI(title="Enrollment Office API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://innolk.up.railway.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    profile = relationship("Profile", uselist=False, back_populates="user")
    requests = relationship("EnrollmentRequest", back_populates="user")


class Profile(Base):
    __tablename__ = "profiles"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    first_name = Column(String)
    middle_name = Column(String, nullable=True)
    last_name = Column(String)
    date_of_birth = Column(String)
    state = Column(String)
    city = Column(String)
    school = Column(String)
    class_number = Column(Integer)
    contact_number = Column(String)
    address = Column(String, nullable=True)
    parents = Column(Text, nullable=True)

    user = relationship("UserDB", back_populates="profile")


class EnrollmentRequest(Base):
    __tablename__ = "requests"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

    achievements = Column(Text, nullable=True)
    motivation_letter = Column(String, nullable=True)
    grades = Column(Text, nullable=True)
    state_exam = Column(String, nullable=True)
    official_grades_document = Column(String, nullable=True)
    admin_note = Column(Text, nullable=True)

    user = relationship("UserDB", back_populates="requests")


Base.metadata.create_all(bind=engine)


class ParentData(BaseModel):
    first_name: str
    last_name: str
    contact_number: Optional[str]
    email: Optional[EmailStr]
    relation: Optional[str]


class RegisterSchema(BaseModel):
    email: EmailStr
    password: constr(min_length=8, max_length=72)


class Token(BaseModel):
    access_token: str
    token_type: str


class ProfileIn(BaseModel):
    first_name: str
    middle_name: Optional[str] = None
    last_name: str
    date_of_birth: str  # We'll validate manually below
    state: str
    city: str
    school: str
    class_number: conint(ge=6, le=10)
    contact_number: str
    address: Optional[str] = None
    parents: List[ParentData]

    @validator("date_of_birth")
    @classmethod
    def validate_date(cls, v: str) -> str:
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", v):
            raise ValueError("date_of_birth must be in YYYY-MM-DD format")
        return v

    @validator("parents")
    @classmethod
    def check_parents(cls, v):
        if not v or len(v) == 0:
            raise ValueError("At least one parent must be provided")
        return v


class RequestStatusUpdate(BaseModel):
    status: str
    admin_note: Optional[str] = None

    @validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        allowed = {"pending", "approved", "denied"}
        if v not in allowed:
            raise ValueError(f"status must be one of {allowed}")
        return v

class LoginRequest(BaseModel):
    email: str
    password: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    # Обрезаем пароль до 72 байт для bcrypt
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    return pwd_context.hash(password_bytes)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def send_email_async(subject: str, recipient: str, body: str):
    message = MessageSchema(
        subject=subject,
        recipients=[recipient],
        body=body,
        subtype="plain"
    )

    fm = FastMail(conf)
    try:
        await fm.send_message(message)
        print(f"✅ Email sent to {recipient}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

def validate_file_upload(file: UploadFile):
    filename = file.filename
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400, detail=f"File type .{ext} not allowed")

    return ext


def save_upload_file(file: UploadFile, dest_folder: str, dest_filename: Optional[str] = None) -> str:
    os.makedirs(dest_folder, exist_ok=True)
    ext = file.filename.rsplit(
        '.', 1)[-1].lower() if '.' in file.filename else ''
    name = dest_filename or f"{uuid.uuid4().hex}.{ext}"
    path = os.path.join(dest_folder, name)
    with open(path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    return path


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> UserDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = int(payload.get("sub"))
        if user_id is None:
            raise credentials_exception
    except (JWTError, Exception):
        raise credentials_exception
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user


def get_admin_user(current_user: UserDB = Depends(get_current_user)) -> UserDB:
    if not current_user.is_admin:
        raise HTTPException(
            status_code=403, detail="Admin privileges required")
    return current_user


@app.post("/token-json", response_model=Token)
def login_for_access_token_json(
    credentials: LoginRequest,
    db: Session = Depends(get_db)
):
    user = db.query(UserDB).filter(UserDB.email == credentials.email).first()

    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=400,
            detail="Incorrect email or password"
        )

    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/register", status_code=201)
def register(data: RegisterSchema, db: Session = Depends(get_db)):
    existing = db.query(UserDB).filter(UserDB.email == data.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = UserDB(email=data.email,
                  hashed_password=get_password_hash(data.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"msg": "User created", "id": user.id}


@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/password-reset/request")
async def password_reset_request(email: EmailStr, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.email == email).first()
    if not user:
        return {"msg": "If an account with that email exists, a reset link will be sent."}
    token = create_access_token(
        {"sub": str(user.id)}, expires_delta=timedelta(hours=2))
    link = f"http://localhost:5173/reset-password?token={token}"
    body = (
        f"To reset your password visit: {link}\n"
        f"This link expires in 2 hours."
    )
    asyncio.create_task(send_email_async(
        "Password reset", user.email, body))
    return {"msg": "If an account with that email exists, a reset link will be sent."}


@app.post("/password-reset/confirm")
def password_reset_confirm(token: str = Form(...), new_password: str = Form(...), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid token")
    user.hashed_password = get_password_hash(new_password)
    db.add(user)
    db.commit()
    return {"msg": "Password reset successful"}


@app.put("/profile", status_code=200)
def update_profile(profile: ProfileIn, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        print(f"Updating profile for user {current_user.id}")
        print(f"Received data: {profile.dict()}")
        
        p = db.query(Profile).filter(Profile.user_id == current_user.id).first()
        if not p:
            p = Profile(user_id=current_user.id)
            print("Creating new profile")
        else:
            print("Updating existing profile")
            
        p.first_name = profile.first_name
        p.middle_name = profile.middle_name
        p.last_name = profile.last_name
        p.date_of_birth = profile.date_of_birth
        p.state = profile.state
        p.city = profile.city
        p.school = profile.school
        p.class_number = profile.class_number
        p.contact_number = profile.contact_number
        p.address = profile.address
        
        import json
        parents_json = json.dumps([par.dict() for par in profile.parents])
        p.parents = parents_json
        
        db.add(p)
        db.commit()
        db.refresh(p)
        
        print("Profile updated successfully")
        return {"msg": "Profile updated"}
        
    except Exception as e:
        print(f"Error updating profile: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.post("/requests/submit")
def submit_request(
    achievements: List[UploadFile] = File([]),
    motivation_letter: UploadFile = File(...),
    grades_file: UploadFile = File(...),
    state_exam_file: Optional[UploadFile] = File(None),
    official_grades_file: Optional[UploadFile] = File(None),
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    print(f"=== SUBMIT REQUEST STARTED ===")
    print(f"User: {current_user.email}")
    print(f"User class: {current_user.profile.class_number if current_user.profile else 'No profile'}")
    
    # Логируем информацию о файлах
    print(f"Achievements count: {len(achievements)}")
    for i, achievement in enumerate(achievements):
        print(f"Achievement {i}: {achievement.filename}")
    
    print(f"Motivation letter: {motivation_letter.filename}")
    print(f"Grades file: {grades_file.filename}")
    print(f"State exam file: {state_exam_file.filename if state_exam_file else 'None'}")
    print(f"Official grades file: {official_grades_file.filename if official_grades_file else 'None'}")
    
    if not current_user.profile:
        raise HTTPException(
            status_code=400, detail="Complete your profile first")
    class_num = current_user.profile.class_number
    if class_num == 10 and state_exam_file is None:
        raise HTTPException(
            status_code=400, detail="State exam results required for class 10")
    if class_num > 8 and official_grades_file is None:
        raise HTTPException(
            status_code=400, detail="Official grades document required for class >8")

    saved_achievements = []
    for file in achievements:
        validate_file_upload(file)
        file.file.seek(0, os.SEEK_END)
        size = file.file.tell()
        file.file.seek(0)
        if size > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail=f"File {file.filename} exceeds 10MB")
        path = save_upload_file(
            file, os.path.join(STORAGE_DIR, 'achievements'))
        saved_achievements.append(path)

    validate_file_upload(motivation_letter)
    motivation_letter.file.seek(0, os.SEEK_END)
    ml_size = motivation_letter.file.tell()
    motivation_letter.file.seek(0)
    if ml_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400, detail="Motivation letter exceeds 10MB")
    fn_ext = motivation_letter.filename.rsplit('.', 1)[-1]
    safe_name = f"{current_user.profile.first_name}_{current_user.profile.last_name}_Motivation_letter.{fn_ext}"
    ml_path = save_upload_file(motivation_letter, os.path.join(
        STORAGE_DIR, 'motivation_letters'), safe_name)

    validate_file_upload(grades_file)
    grades_file.file.seek(0, os.SEEK_END)
    g_size = grades_file.file.tell()
    grades_file.file.seek(0)
    if g_size > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="Grades file exceeds 10MB")
    grades_path = save_upload_file(
        grades_file, os.path.join(STORAGE_DIR, 'grades'))

    state_exam_path = None
    if state_exam_file:
        validate_file_upload(state_exam_file)
        if state_exam_file.file.seek(0, os.SEEK_END) and state_exam_file.file.tell() > MAX_FILE_SIZE:
            state_exam_file.file.seek(0)
            raise HTTPException(
                status_code=400, detail="State exam file exceeds 10MB")
        state_exam_file.file.seek(0)
        state_exam_path = save_upload_file(
            state_exam_file, os.path.join(STORAGE_DIR, 'state_exams'))

    official_grades_path = None
    if official_grades_file:
        validate_file_upload(official_grades_file)
        official_grades_file.file.seek(0, os.SEEK_END)
        if official_grades_file.file.tell() > MAX_FILE_SIZE:
            official_grades_file.file.seek(0)
            raise HTTPException(
                status_code=400, detail="Official grades file exceeds 10MB")
        official_grades_file.file.seek(0)
        official_grades_path = save_upload_file(
            official_grades_file, os.path.join(STORAGE_DIR, 'official_grades'))

    req = EnrollmentRequest(
        user_id=current_user.id,
        achievements='|'.join(saved_achievements),
        motivation_letter=ml_path,
        grades=grades_path,
        state_exam=state_exam_path,
        official_grades_document=official_grades_path,
        status='pending'
    )
    db.add(req)
    db.commit()
    db.refresh(req)
    return {"msg": "Request submitted", "request_id": req.id}


@app.get("/requests/me")
def list_my_requests(current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    reqs = db.query(EnrollmentRequest).filter(
        EnrollmentRequest.user_id == current_user.id).all()
    out = []
    for r in reqs:
        out.append({
            "id": r.id,
            "status": r.status,
            "created_at": r.created_at,
            "updated_at": r.updated_at
        })
    return out


@app.post("/admin/login", response_model=Token)
def admin_login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(
        UserDB.email == form_data.username, 
        UserDB.is_admin == True  # Исправлено с is на ==
    ).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=400, detail="Incorrect admin credentials")
    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/admin/requests")
def admin_list_requests(status: Optional[str] = None, state: Optional[str] = None, db: Session = Depends(get_db), admin: UserDB = Depends(get_admin_user)):
    # Используем joinedload для загрузки связанных данных
    from sqlalchemy.orm import joinedload
    
    q = db.query(EnrollmentRequest).options(
        joinedload(EnrollmentRequest.user).joinedload(UserDB.profile)
    )
    
    if status:
        q = q.filter(EnrollmentRequest.status == status)
    if state:
        q = q.join(UserDB).join(Profile).filter(Profile.state == state)
    
    results = q.order_by(EnrollmentRequest.created_at.desc()).all()
    out = []
    for r in results:
        user_data = {
            "id": r.id,
            "user_id": r.user_id,
            "status": r.status,
            "created_at": r.created_at
        }
        
        # Добавляем данные пользователя, если они есть
        if r.user and r.user.profile:
            user_data.update({
                "user_email": r.user.email,
                "profile": {
                    "first_name": r.user.profile.first_name,
                    "last_name": r.user.profile.last_name,
                    "state": r.user.profile.state,
                    "city": r.user.profile.city,
                    "school": r.user.profile.school,
                    "class_number": r.user.profile.class_number,
                    "contact_number": r.user.profile.contact_number
                }
            })
        
        out.append(user_data)
    
    return out

@app.get("/admin/request/{request_id}")
def admin_get_request(request_id: int, db: Session = Depends(get_db), admin: UserDB = Depends(get_admin_user)):
    from sqlalchemy.orm import joinedload
    
    r = db.query(EnrollmentRequest).options(
        joinedload(EnrollmentRequest.user).joinedload(UserDB.profile)
    ).filter(EnrollmentRequest.id == request_id).first()
    
    if not r:
        raise HTTPException(status_code=404, detail="Request not found")
    
    response_data = {
        "id": r.id,
        "user_id": r.user_id,
        "status": r.status,
        "achievements": r.achievements.split('|') if r.achievements else [],
        "motivation_letter": r.motivation_letter,
        "grades": r.grades,
        "state_exam": r.state_exam,
        "official_grades_document": r.official_grades_document,
        "admin_note": r.admin_note
    }
    
    # Добавляем данные пользователя, если они есть
    if r.user:
        response_data["user"] = {
            "email": r.user.email
        }
        if r.user.profile:
            response_data["user"]["profile"] = {
                "first_name": r.user.profile.first_name,
                "last_name": r.user.profile.last_name,
                "state": r.user.profile.state,
                "city": r.user.profile.city,
                "school": r.user.profile.school,
                "class_number": r.user.profile.class_number,
                "contact_number": r.user.profile.contact_number
            }
    
    return response_data

@app.post("/admin/request/{request_id}/status")
def admin_update_status(request_id: int, update: RequestStatusUpdate, db: Session = Depends(get_db), admin: UserDB = Depends(get_admin_user)):
    r = db.query(EnrollmentRequest).filter(
        EnrollmentRequest.id == request_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Request not found")
    r.status = update.status
    r.admin_note = update.admin_note
    r.updated_at = datetime.utcnow()
    db.add(r)
    db.commit()
    user = db.query(UserDB).filter(UserDB.id == r.user_id).first()
    if user:
        subject = f"Your enrollment request #{r.id} status: {r.status}"
        body = f"Hello, your request status changed to {r.status}.\nAdmin note: {r.admin_note or ''}"
        BackgroundTasks().add_task(lambda: send_email_async(subject, user.email, body))
    return {"msg": "Status updated"}


@app.post("/admin/notify/{user_id}")
def admin_notify_user(user_id: int, subject: str = Form(...), body: str = Form(...), db: Session = Depends(get_db), admin: UserDB = Depends(get_admin_user)):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    BackgroundTasks().add_task(lambda: send_email_async(subject, user.email, body))
    return {"msg": "Notification scheduled"}


@app.get("/admin/export/users.xlsx")
def admin_export_users(db: Session = Depends(get_db), admin: UserDB = Depends(get_admin_user)):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["user_id", "email", "first_name", "last_name", "state",
              "city", "school", "class", "contact", "created_at"])
    users = db.query(UserDB).all()
    for u in users:
        p = u.profile
        ws.append([
            u.id,
            u.email,
            p.first_name if p else None,
            p.last_name if p else None,
            p.state if p else None,
            p.city if p else None,
            p.school if p else None,
            p.class_number if p else None,
            p.contact_number if p else None,
            u.created_at.isoformat()
        ])
    stream = io.BytesIO()
    wb.save(stream)
    stream.seek(0)
    headers = {"Content-Disposition": "attachment; filename=users.xlsx"}
    return StreamingResponse(stream, media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', headers=headers)


@app.get("/admin/export/motivation_letters.zip")
def admin_export_motivation_zip(db: Session = Depends(get_db), admin: UserDB = Depends(get_admin_user)):
    reqs = db.query(EnrollmentRequest).filter(
        EnrollmentRequest.motivation_letter is not None).all()
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, mode="w") as zf:
        for r in reqs:
            path = r.motivation_letter
            if path and os.path.exists(path):
                arcname = os.path.basename(path)
                zf.write(path, arcname=arcname)
    mem.seek(0)
    headers = {
        "Content-Disposition": "attachment; filename=motivation_letters.zip"}
    return StreamingResponse(mem, media_type="application/zip", headers=headers)


@app.get("/admin/stats")
def admin_stats(db: Session = Depends(get_db), admin: UserDB = Depends(get_admin_user)):
    total = db.query(EnrollmentRequest).count()
    from sqlalchemy import func
    status_counts = db.query(EnrollmentRequest.status, func.count(
        EnrollmentRequest.id)).group_by(EnrollmentRequest.status).all()
    status_counts = {s: c for s, c in status_counts}
    state_counts = db.query(Profile.state, func.count(Profile.id)).join(UserDB).join(
        EnrollmentRequest, EnrollmentRequest.user_id == UserDB.id).group_by(Profile.state).all()
    state_counts = {s: c for s, c in state_counts}
    times = db.query(EnrollmentRequest).filter(
        EnrollmentRequest.status.in_(["approved", "denied"])).all()
    import statistics
    durations = []
    for r in times:
        if r.updated_at and r.created_at:
            durations.append((r.updated_at - r.created_at).total_seconds())
    avg_processing_seconds = statistics.mean(durations) if durations else None
    return {"total_requests": total, "status_counts": status_counts, "state_counts": state_counts, "avg_processing_seconds": avg_processing_seconds}


@app.get("/admin/file")
def admin_get_file(path: str, db: Session = Depends(get_db), admin: UserDB = Depends(get_admin_user)):
    full = os.path.abspath(path)
    if not full.startswith(STORAGE_DIR):
        raise HTTPException(status_code=400, detail="Invalid path")
    if not os.path.exists(full):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(full)

@app.get("/profile")
def get_profile(current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    profile = db.query(Profile).filter(Profile.user_id == current_user.id).first()
    
    # Если профиль не найден, возвращаем пустой объект вместо ошибки 404
    if not profile:
        return {
            "first_name": "",
            "middle_name": "",
            "last_name": "",
            "date_of_birth": "",
            "state": "",
            "city": "",
            "school": "",
            "class_number": 6,  # значение по умолчанию
            "contact_number": "",
            "address": "",
            "parents": []
        }
    
    import json
    return {
        "first_name": profile.first_name,
        "middle_name": profile.middle_name,
        "last_name": profile.last_name,
        "date_of_birth": profile.date_of_birth,
        "state": profile.state,
        "city": profile.city,
        "school": profile.school,
        "class_number": profile.class_number,
        "contact_number": profile.contact_number,
        "address": profile.address,
        "parents": json.loads(profile.parents) if profile.parents else []
    }

@app.get("/")
def root():
    return {"msg": "Enrollment API up"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000)
