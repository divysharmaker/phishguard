from motor.motor_asyncio import AsyncIOMotorClient
from config import settings

client: AsyncIOMotorClient = None
db = None

async def connect_db():
    global client, db
    client = AsyncIOMotorClient(settings.MONGO_URI)
    db = client[settings.DB_NAME]
    # Create indexes for faster queries
    await db.users.create_index("email", unique=True)
    await db.scans.create_index("user_id")
    await db.scans.create_index("scanned_at")
    print(f"✅  Connected to MongoDB — database: '{settings.DB_NAME}'")

async def close_db():
    global client
    if client:
        client.close()
        print("MongoDB connection closed.")

def get_db():
    return db
