from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel, EmailStr
from datetime import datetime, timezone
from database import get_db
from auth import hash_password, verify_password, create_access_token, get_current_user

router = APIRouter()

# ── Schemas ──────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

# ───────── REGISTER ─────────
@router.post("/register", status_code=201)
async def register(body: RegisterRequest, db=Depends(get_db)):
    existing = await db.users.find_one({"email": body.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    if len(body.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    user_doc = {
        "name":           body.name.strip(),
        "email":          body.email.lower(),
        "password":       hash_password(body.password),
        "created_at":     datetime.now(timezone.utc),
        "total_scans":    0,
        "phishing_found": 0,
    }
    result = await db.users.insert_one(user_doc)

    token = create_access_token({"sub": body.email.lower()})
    return {
        "token": token,
        "user": {
            "id":    str(result.inserted_id),
            "name":  user_doc["name"],
            "email": user_doc["email"],
        }
    }

# ───────── LOGIN ─────────
@router.post("/login")
async def login(body: LoginRequest, db=Depends(get_db)):
    user = await db.users.find_one({"email": body.email.lower()})
    if not user or not verify_password(body.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token({"sub": user["email"]})
    return {
        "token": token,
        "user": {
            "id":    str(user["_id"]),
            "name":  user["name"],
            "email": user["email"],
        }
    }

# ───────── ME ─────────
@router.get("/me")
async def me(current_user=Depends(get_current_user)):
    return {
        "id":             str(current_user["_id"]),
        "name":           current_user["name"],
        "email":          current_user["email"],
        "total_scans":    current_user.get("total_scans", 0),
        "phishing_found": current_user.get("phishing_found", 0),
    }