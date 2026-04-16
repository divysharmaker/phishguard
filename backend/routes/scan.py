from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from typing import List
from datetime import datetime, timezone
import re

from database import get_db
from backend.routes.auth import get_current_user
from detector import run_prediction

router = APIRouter()

# ── Input sanitization ────────────────────────────────────────
URL_RE = re.compile(
    r'^(https?://)?'
    r'('
      r'(\d{1,3}\.){3}\d{1,3}'          # IPv4
      r'|'
      r'([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}'# domain
    r')'
    r'(:\d{1,5})?(/[^\s<>\"]*)?'
    r'(\?[^\s<>\"]*)?$'
)

def sanitize_url(raw: str) -> str:
    url = raw.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    if len(url) > 2048:
        raise HTTPException(status_code=400, detail="URL too long (max 2048 characters)")
    test = url if url.startswith(('http://', 'https://')) else 'http://' + url
    # Basic check — very permissive on purpose so detector can analyse weird URLs
    if not re.search(r'[a-zA-Z0-9]', url):
        raise HTTPException(status_code=400, detail="Invalid URL format")
    return url

class ScanRequest(BaseModel):
    url: str

    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        v = v.strip()
        if not v:
            raise ValueError('URL cannot be empty')
        if len(v) > 2048:
            raise ValueError('URL too long (max 2048 characters)')
        return v

class BatchScanRequest(BaseModel):
    urls: List[str]

    @field_validator('urls')
    @classmethod
    def validate_urls(cls, v):
        if not v:
            raise ValueError('URL list cannot be empty')
        if len(v) > 50:
            raise ValueError('Maximum 50 URLs per batch')
        return [u.strip() for u in v if u.strip()]

# ── Endpoints ─────────────────────────────────────────────────
@router.post("/single")
async def scan_single(
    request: Request,
    body: ScanRequest,
    current_user=Depends(get_current_user),
    db=Depends(get_db),
):
    url = sanitize_url(body.url)
    result = await run_prediction(url)

    scan_doc = {
        "user_id":     str(current_user["_id"]),
        "url":         result["url"],
        "verdict":     result["verdict"],
        "final_proba": result["final_proba"],
        "url_risk":    result["url_risk"],
        "model_proba": result["model_proba"],
        "flags":       result["flags"],
        "features":    result["features"],
        "scan_type":   "single",
        "scanned_at":  datetime.now(timezone.utc),
    }
    await db.scans.insert_one(scan_doc)

    is_phishing = result["verdict"] == "PHISHING"
    await db.users.update_one(
        {"_id": current_user["_id"]},
        {"$inc": {"total_scans": 1, "phishing_found": 1 if is_phishing else 0}}
    )
    return result

@router.post("/batch")
async def scan_batch(
    request: Request,
    body: BatchScanRequest,
    current_user=Depends(get_current_user),
    db=Depends(get_db),
):
    results = []
    scan_docs = []
    phishing_count = 0

    for raw_url in body.urls:
        try:
            url = sanitize_url(raw_url)
        except HTTPException:
            continue
        result = await run_prediction(url)
        results.append(result)
        if result["verdict"] == "PHISHING":
            phishing_count += 1
        scan_docs.append({
            "user_id":     str(current_user["_id"]),
            "url":         result["url"],
            "verdict":     result["verdict"],
            "final_proba": result["final_proba"],
            "url_risk":    result["url_risk"],
            "model_proba": result["model_proba"],
            "flags":       result["flags"],
            "features":    result["features"],
            "scan_type":   "batch",
            "scanned_at":  datetime.now(timezone.utc),
        })

    if scan_docs:
        await db.scans.insert_many(scan_docs)
        await db.users.update_one(
            {"_id": current_user["_id"]},
            {"$inc": {"total_scans": len(scan_docs), "phishing_found": phishing_count}}
        )

    summary = {
        "total":      len(results),
        "phishing":   sum(1 for r in results if r["verdict"] == "PHISHING"),
        "suspicious": sum(1 for r in results if r["verdict"] == "SUSPICIOUS"),
        "safe":       sum(1 for r in results if r["verdict"] in ["SAFE", "TRUSTED"]),
    }
    return {"results": results, "summary": summary}