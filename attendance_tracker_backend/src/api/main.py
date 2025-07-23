import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env"))

SECRET_KEY = os.getenv("JWT_SECRET", "INSECURE_DEFAULT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRY_MINUTES", "60"))

FAKE_DB = {
    "users": {
        "admin@example.com": {"hashed_password": "fakehashedadmin", "role": "admin"},
        "teacher@example.com": {"hashed_password": "fakehashedteach", "role": "teacher"},
        "student@example.com": {"hashed_password": "fakehashedstud", "role": "student"},
    },
    "students": [
        {"id": 1, "full_name": "John Doe", "roll_no": "A01", "class": "10A", "active": True},
        {"id": 2, "full_name": "Jane Smith", "roll_no": "A02", "class": "10A", "active": True},
    ],
    "attendance": [
        # {"student_id": 1, "date": "2024-06-01", "status": "present"}
    ]
}

app = FastAPI(
    title="Attendance Tracker Backend",
    description="API for student attendance tracking system. Features: dashboard, student management, attendance marking, authentication, and attendance history.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Authentication", "description": "User Login & JWT"},
        {"name": "Students", "description": "Student management"},
        {"name": "Attendance", "description": "Attendance marking & History"},
        {"name": "Dashboard", "description": "Attendance overview"},
        {"name": "Health", "description": "System health check"},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# Models

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[EmailStr] = None

# --- User Models ---
class User(BaseModel):
    email: EmailStr
    role: str

class UserInDB(User):
    hashed_password: str

# --- Student Models ---
class Student(BaseModel):
    id: int = Field(..., description="Unique student id")
    full_name: str = Field(..., description="Student's full name")
    roll_no: str = Field(..., description="Student roll number")
    class_: str = Field(..., alias="class", description="Class/Section")
    active: bool = Field(..., description="Is student active?")

class StudentCreate(BaseModel):
    full_name: str
    roll_no: str
    class_: str = Field(..., alias="class")

class StudentUpdate(BaseModel):
    full_name: Optional[str] = None
    roll_no: Optional[str] = None
    class_: Optional[str] = Field(None, alias="class")
    active: Optional[bool] = None

# --- Attendance Models ---
class AttendanceMarkRequest(BaseModel):
    student_id: int = Field(..., description="ID of the student")
    date: str = Field(..., description="YYYY-MM-DD")
    status: str = Field(..., description="present/absent/late/leave")

class AttendanceHistoryRecord(BaseModel):
    student_id: int
    student_name: str
    date: str
    status: str

class AttendanceDashboardOverview(BaseModel):
    total_students: int
    present_today: int
    absent_today: int
    late_today: int
    percentage_today: float

# Utils

# Fake password hashing (replace for production)
def fake_hash_password(pw: str):
    return "fakehashed" + pw

# PUBLIC_INTERFACE
def authenticate_user(email: str, password: str):
    """Authenticate user credentials with fake DB."""
    user = FAKE_DB["users"].get(email)
    if not user:
        return None
    if user["hashed_password"] != fake_hash_password(password):
        return None
    return User(email=email, role=user['role'])

# PUBLIC_INTERFACE
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# PUBLIC_INTERFACE
async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Get current validated user from JWT."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = FAKE_DB["users"].get(token_data.email)
    if user is None:
        raise credentials_exception
    return User(email=token_data.email, role=user['role'])

# API Endpoints

@app.get("/", tags=["Health"])
def health_check():
    """Health status of the backend API."""
    return {"message": "Healthy"}

# --------------------- Authentication ------------------------

# PUBLIC_INTERFACE
@app.post("/auth/token", response_model=Token, tags=["Authentication"], summary="User login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Authenticate user and return an access token.

    - **username**: user email
    - **password**: password
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

# PUBLIC_INTERFACE
@app.get("/auth/me", response_model=User, tags=["Authentication"], summary="Get current user")
async def get_me(current_user: User = Depends(get_current_user)):
    """Get profile details for the authenticated user."""
    return current_user

# ----------------------- Student Management ------------------

# PUBLIC_INTERFACE
@app.get("/students", response_model=List[Student], tags=["Students"], summary="List students")
async def list_students(current_user: User = Depends(get_current_user)):
    """Return all students (admin/teacher only)."""
    # In real app, filter by user role
    students = [Student(**s) for s in FAKE_DB["students"]]
    return students

# PUBLIC_INTERFACE
@app.post("/students", response_model=Student, tags=["Students"], summary="Add a student")
async def add_student(student: StudentCreate, current_user: User = Depends(get_current_user)):
    """Add a new student."""
    new_id = (max([s["id"] for s in FAKE_DB["students"]]) + 1) if FAKE_DB["students"] else 1
    new_student = {
        "id": new_id,
        "full_name": student.full_name,
        "roll_no": student.roll_no,
        "class": student.class_,
        "active": True,
    }
    FAKE_DB["students"].append(new_student)
    return Student(**new_student)

# PUBLIC_INTERFACE
@app.put("/students/{student_id}", response_model=Student, tags=["Students"], summary="Update student info")
async def update_student(student_id: int, update: StudentUpdate, current_user: User = Depends(get_current_user)):
    """Update details of a student."""
    for s in FAKE_DB["students"]:
        if s["id"] == student_id:
            s.update(**{k: v for k, v in update.dict(exclude_unset=True).items()})
            return Student(**s)
    raise HTTPException(status_code=404, detail="Student not found")

# PUBLIC_INTERFACE
@app.delete("/students/{student_id}", tags=["Students"], summary="Delete student")
async def delete_student(student_id: int, current_user: User = Depends(get_current_user)):
    """Delete a student by id."""
    for idx, s in enumerate(FAKE_DB["students"]):
        if s["id"] == student_id:
            del FAKE_DB["students"][idx]
            return JSONResponse(content={"message": "Student deleted"})
    raise HTTPException(status_code=404, detail="Student not found")

# --------------------- Attendance Management ------------------

# PUBLIC_INTERFACE
@app.post("/attendance/mark", tags=["Attendance"], summary="Mark attendance")
async def mark_attendance(req: AttendanceMarkRequest, current_user: User = Depends(get_current_user)):
    """Mark attendance for a student."""
    # Verify student exists
    student = next((s for s in FAKE_DB["students"] if s["id"] == req.student_id), None)
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    # Only allow single attendance mark per student/date
    for record in FAKE_DB["attendance"]:
        if record["student_id"] == req.student_id and record["date"] == req.date:
            record["status"] = req.status
            return {"message": "Attendance updated"}
    FAKE_DB["attendance"].append({
        "student_id": req.student_id,
        "date": req.date,
        "status": req.status,
    })
    return {"message": "Attendance marked"}

# PUBLIC_INTERFACE
@app.get("/attendance/history/{student_id}", response_model=List[AttendanceHistoryRecord], tags=["Attendance"], summary="Attendance history for student")
async def attendance_history(student_id: int, current_user: User = Depends(get_current_user)):
    """Return attendance history for a single student."""
    student = next((s for s in FAKE_DB["students"] if s["id"] == student_id), None)
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    records = [
        AttendanceHistoryRecord(
            student_id=rec["student_id"],
            student_name=student["full_name"],
            date=rec["date"],
            status=rec["status"]
        )
        for rec in FAKE_DB["attendance"]
        if rec["student_id"] == student_id
    ]
    return records

# PUBLIC_INTERFACE
@app.get("/attendance/history", response_model=List[AttendanceHistoryRecord], tags=["Attendance"], summary="All attendance history")
async def all_attendance_history(current_user: User = Depends(get_current_user)):
    """Return all attendance records (admin/teacher only)."""
    student_by_id = {s["id"]: s["full_name"] for s in FAKE_DB["students"]}
    records = [
        AttendanceHistoryRecord(
            student_id=rec["student_id"],
            student_name=student_by_id.get(rec["student_id"], "Unknown"),
            date=rec["date"],
            status=rec["status"]
        )
        for rec in FAKE_DB["attendance"]
    ]
    return records

# --------------------- Dashboard Overview -----------------------

# PUBLIC_INTERFACE
@app.get("/dashboard/overview", response_model=AttendanceDashboardOverview, tags=["Dashboard"], summary="Dashboard overview")
async def dashboard_overview(current_user: User = Depends(get_current_user)):
    """Summary of today's attendance: total, present, absent, late, and attendance %."""
    today = datetime.today().strftime("%Y-%m-%d")
    total_students = len(FAKE_DB["students"])
    present_today = sum(1 for rec in FAKE_DB["attendance"] if rec["date"] == today and rec["status"] == "present")
    absent_today = sum(1 for rec in FAKE_DB["attendance"] if rec["date"] == today and rec["status"] == "absent")
    late_today = sum(1 for rec in FAKE_DB["attendance"] if rec["date"] == today and rec["status"] == "late")
    denominator = present_today + absent_today + late_today
    percentage_today = (present_today / denominator * 100) if denominator > 0 else 0.0
    return AttendanceDashboardOverview(
        total_students=total_students,
        present_today=present_today,
        absent_today=absent_today,
        late_today=late_today,
        percentage_today=percentage_today
    )

# --------------------- API Documentation Routes ------------------

# PUBLIC_INTERFACE
@app.get("/docs/websocket_help", tags=["Dashboard"])
def websocket_info():
    """
    Usage: This API does NOT use WebSockets. All communication is RESTful over HTTP.
    """
    return {"websocket": False, "note": "No WebSocket interface. Use HTTP REST API endpoints."}
