from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
import uvicorn

# ✅ CORRECT IMPORTS (NO backend.)
from database import connect_db, close_db
from routes.auth import router as auth_router
from routes.scan import router as scan_router
from routes.history import router as history_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()

app = FastAPI(
    title="PhishGuard AI",
    description="Phishing URL Detection API",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "https://ubiquitous-shortbread-ea41db.netlify.app",
        "https://neon-unicorn-bc332f.netlify.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/api/auth", tags=["Auth"])
app.include_router(scan_router, prefix="/api/scan", tags=["Scan"])
app.include_router(history_router, prefix="/api/history", tags=["History"])

@app.get("/")
async def root():
    return {
        "message": "PhishGuard AI API is running",
        "version": "2.0.0"
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)