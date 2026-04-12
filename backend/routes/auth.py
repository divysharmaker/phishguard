from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, EmailStr
from datetime import datetime, timezone
from bson import ObjectId
from database import get_db
from auth import hash_password, verify_password, create_access_token, get_current_user, get_admin_user

router = APIRouter()

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

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
        "role":           "user",
        "is_active":      True,
        "last_login":     None,
        "login_history":  [],
    }
    result = await db.users.insert_one(user_doc)
    token = create_access_token({"sub": body.email.lower(), "role": "user"})
    return {
        "token": token,
        "user": {"id": str(result.inserted_id), "name": user_doc["name"], "email": user_doc["email"], "role": "user"}
    }

@router.post("/login")
async def login(body: LoginRequest, db=Depends(get_db)):
    user = await db.users.find_one({"email": body.email.lower()})
    if not user or not verify_password(body.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account has been deactivated by admin")
    now = datetime.now(timezone.utc)
    await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {"last_login": now}, "$push": {"login_history": {"$each": [{"logged_in_at": now}], "$slice": -20}}}
    )
    token = create_access_token({"sub": user["email"], "role": user.get("role", "user")})
    return {
        "token": token,
        "user": {"id": str(user["_id"]), "name": user["name"], "email": user["email"], "role": user.get("role", "user")}
    }

@router.get("/me")
async def me(current_user=Depends(get_current_user)):
    return {
        "id":             str(current_user["_id"]),
        "name":           current_user["name"],
        "email":          current_user["email"],
        "role":           current_user.get("role", "user"),
        "total_scans":    current_user.get("total_scans", 0),
        "phishing_found": current_user.get("phishing_found", 0),
        "last_login":     current_user.get("last_login", "").isoformat() if current_user.get("last_login") else None,
    }

@router.delete("/delete-account")
async def delete_account(current_user=Depends(get_current_user), db=Depends(get_db)):
    if current_user.get("role") == "admin":
        raise HTTPException(status_code=400, detail="Admin account cannot be deleted")
    uid = str(current_user["_id"])
    await db.scans.delete_many({"user_id": uid})
    await db.users.delete_one({"_id": current_user["_id"]})
    return {"message": "Account deleted successfully"}

# ── Admin Routes ──────────────────────────────────────────────
@router.get("/admin/users")
async def admin_get_users(admin=Depends(get_admin_user), db=Depends(get_db)):
    cursor = db.users.find({}, sort=[("created_at", -1)])
    users = await cursor.to_list(length=200)
    result = []
    for u in users:
        result.append({
            "id":             str(u["_id"]),
            "name":           u["name"],
            "email":          u["email"],
            "role":           u.get("role", "user"),
            "is_active":      u.get("is_active", True),
            "total_scans":    u.get("total_scans", 0),
            "phishing_found": u.get("phishing_found", 0),
            "created_at":     u["created_at"].isoformat() if u.get("created_at") else None,
            "last_login":     u["last_login"].isoformat() if u.get("last_login") else None,
            "login_count":    len(u.get("login_history", [])),
        })
    return result

@router.get("/admin/stats")
async def admin_stats(admin=Depends(get_admin_user), db=Depends(get_db)):
    total_users    = await db.users.count_documents({"role": {"$ne": "admin"}})
    total_scans    = await db.scans.count_documents({})
    total_phishing = await db.scans.count_documents({"verdict": "PHISHING"})
    active_users   = await db.users.count_documents({"is_active": True, "role": {"$ne": "admin"}})
    return {"total_users": total_users, "active_users": active_users, "total_scans": total_scans, "total_phishing": total_phishing}

@router.delete("/admin/users/{user_id}")
async def admin_delete_user(user_id: str, admin=Depends(get_admin_user), db=Depends(get_db)):
    await db.scans.delete_many({"user_id": user_id})
    await db.users.delete_one({"_id": ObjectId(user_id)})
    return {"message": "User deleted"}

@router.patch("/admin/users/{user_id}/toggle")
async def admin_toggle_user(user_id: str, admin=Depends(get_admin_user), db=Depends(get_db)):
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    new_status = not user.get("is_active", True)
    await db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"is_active": new_status}})
    return {"is_active": new_status}

@router.get("/admin/user/{user_id}/scans")
async def admin_user_scans(user_id: str, admin=Depends(get_admin_user), db=Depends(get_db)):
    cursor = db.scans.find({"user_id": user_id}, sort=[("scanned_at", -1)], limit=50)
    scans = await cursor.to_list(length=50)
    for s in scans:
        s["id"] = str(s.pop("_id"))
        if hasattr(s.get("scanned_at"), "isoformat"):
            s["scanned_at"] = s["scanned_at"].isoformat()
    return scans
