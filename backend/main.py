from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import uvicorn

from database import connect_db, close_db
from backend.routes.auth    import router as auth_router
from routes.scan    import router as scan_router
from routes.history import router as history_router

# ── Rate limiter ──────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()

app = FastAPI(title="PhishGuard AI", version="2.0.0", lifespan=lifespan)

# Attach limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "https://ubiquitous-shortbread-ea41db.netlify.app",
        "https://neon-unicorn-bc332f.netlify.app",
        "https://phishguard-2026.netlify.app",
        "https://phishguard-app-six.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router,    prefix="/api/auth",    tags=["Auth"])
app.include_router(scan_router,    prefix="/api/scan",    tags=["Scan"])
app.include_router(history_router, prefix="/api/history", tags=["History"])

@app.get("/")
async def root():
    return {"message": "PhishGuard AI API is running", "version": "2.0.0"}

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)