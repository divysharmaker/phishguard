from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List
from datetime import datetime, timezone

from database import get_db
from auth import get_current_user
from detector import run_prediction

router = APIRouter()

class ScanRequest(BaseModel):
    url: str

class BatchScanRequest(BaseModel):
    urls: List[str]

@router.post("/single")
async def scan_single(
    body: ScanRequest,
    current_user=Depends(get_current_user),
    db=Depends(get_db),
):
    if not body.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    result = run_prediction(body.url.strip())

    # Save to scan history
    scan_doc = {
        "user_id":    str(current_user["_id"]),
        "url":        result["url"],
        "verdict":    result["verdict"],
        "final_proba": result["final_proba"],
        "url_risk":   result["url_risk"],
        "model_proba": result["model_proba"],
        "flags":      result["flags"],
        "features":   result["features"],
        "scan_type":  "single",
        "scanned_at": datetime.now(timezone.utc),
    }
    await db.scans.insert_one(scan_doc)

    # Update user counters
    is_phishing = result["verdict"] == "PHISHING"
    await db.users.update_one(
        {"_id": current_user["_id"]},
        {"$inc": {
            "total_scans": 1,
            "phishing_found": 1 if is_phishing else 0,
        }}
    )

    return result


@router.post("/batch")
async def scan_batch(
    body: BatchScanRequest,
    current_user=Depends(get_current_user),
    db=Depends(get_db),
):
    if not body.urls:
        raise HTTPException(status_code=400, detail="URL list cannot be empty")
    if len(body.urls) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 URLs per batch")

    results = []
    scan_docs = []
    phishing_count = 0

    for raw_url in body.urls:
        if not raw_url.strip():
            continue
        result = run_prediction(raw_url.strip())
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
            {"$inc": {
                "total_scans":    len(scan_docs),
                "phishing_found": phishing_count,
            }}
        )

    summary = {
        "total":     len(results),
        "phishing":  sum(1 for r in results if r["verdict"] == "PHISHING"),
        "suspicious":sum(1 for r in results if r["verdict"] == "SUSPICIOUS"),
        "safe":      sum(1 for r in results if r["verdict"] in ["SAFE","TRUSTED"]),
    }

    return {"results": results, "summary": summary}
