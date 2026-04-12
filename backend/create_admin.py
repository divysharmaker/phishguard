import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from datetime import datetime, timezone

MONGO_URI      = "mongodb+srv://divyansh2029:Phish2026secure@cluster0.8qrhy.mongodb.net/phishguard?retryWrites=true&w=majority&appName=Cluster0"
DB_NAME        = "phishguard"
ADMIN_EMAIL    = "divyansh2029@gmail.com"
ADMIN_PASSWORD = "Divu0719"
ADMIN_NAME     = "Divyansh Admin"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def create_admin():
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[DB_NAME]
    existing = await db.users.find_one({"email": ADMIN_EMAIL})
    if existing:
        await db.users.update_one(
            {"email": ADMIN_EMAIL},
            {"$set": {"role": "admin", "password": pwd_context.hash(ADMIN_PASSWORD), "is_active": True}}
        )
        print(f"✅ Admin updated: {ADMIN_EMAIL}")
    else:
        await db.users.insert_one({
            "name": ADMIN_NAME, "email": ADMIN_EMAIL,
            "password": pwd_context.hash(ADMIN_PASSWORD),
            "role": "admin", "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "total_scans": 0, "phishing_found": 0,
            "last_login": None, "login_history": [],
        })
        print(f"✅ Admin created: {ADMIN_EMAIL}")
    print(f"📧 Email: {ADMIN_EMAIL}\n🔑 Password: {ADMIN_PASSWORD}")
    client.close()

asyncio.run(create_admin())
