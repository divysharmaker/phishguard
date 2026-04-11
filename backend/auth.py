from fastapi import APIRouter, HTTPException, status, Depends
from datetime import datetime
from database import get_db
from auth import hash_password, verify_password, create_access_token

router = APIRouter()

# ───────── REGISTER ─────────
@router.post("/register")
async def register(user: dict, db=Depends(get_db)):
    try:
        # check if user already exists
        existing_user = await db.users.find_one({"email": user.get("email")})
        if existing_user:
            raise HTTPException(
                status_code=400,
                detail="User already exists"
            )

        # hash password
        hashed_password = hash_password(user.get("password"))

        # create user document
        new_user = {
            "name": user.get("name"),
            "email": user.get("email"),
            "password": hashed_password,
            "created_at": datetime.utcnow()
        }

        await db.users.insert_one(new_user)

        return {"message": "User registered successfully"}

    except HTTPException:
        raise  # re-raise proper errors

    except Exception as e:
        print("REGISTER ERROR:", e)
        raise HTTPException(
            status_code=500,
            detail="Internal Server Error"
        )


# ───────── LOGIN ─────────
@router.post("/login")
async def login(user: dict, db=Depends(get_db)):
    try:
        # find user
        existing_user = await db.users.find_one({"email": user.get("email")})
        if not existing_user:
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password"
            )

        # verify password
        if not verify_password(user.get("password"), existing_user["password"]):
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password"
            )

        # create token
        token = create_access_token({"sub": existing_user["email"]})

        return {
            "access_token": token,
            "token_type": "bearer"
        }

    except HTTPException:
        raise

    except Exception as e:
        print("LOGIN ERROR:", e)
        raise HTTPException(
            status_code=500,
            detail="Internal Server Error"
        )