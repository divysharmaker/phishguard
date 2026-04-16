from fastapi import APIRouter, Depends, Query
from bson import ObjectId
from datetime import datetime

from database import get_db
from auth import get_current_user

router = APIRouter()

def serialize(doc: dict) -> dict:
    doc["id"] = str(doc.pop("_id"))
    if isinstance(doc.get("scanned_at"), datetime):
        doc["scanned_at"] = doc["scanned_at"].isoformat()
    return doc

@router.get("/")
async def get_history(
    page:  int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    current_user=Depends(get_current_user),
    db=Depends(get_db),
):
    skip = (page - 1) * limit
    uid  = str(current_user["_id"])

    cursor = db.scans.find(
        {"user_id": uid},
        sort=[("scanned_at", -1)],
        skip=skip,
        limit=limit,
    )
    docs  = await cursor.to_list(length=limit)
    total = await db.scans.count_documents({"user_id": uid})

    return {
        "scans":      [serialize(d) for d in docs],
        "total":      total,
        "page":       page,
        "total_pages": (total + limit - 1) // limit,
    }

@router.delete("/")
async def clear_history(
    current_user=Depends(get_current_user),
    db=Depends(get_db),
):
    uid    = str(current_user["_id"])
    result = await db.scans.delete_many({"user_id": uid})
    # Reset user counters too
    await db.users.update_one(
        {"_id": current_user["_id"]},
        {"$set": {"total_scans": 0, "phishing_found": 0}}
    )
    return {"deleted": result.deleted_count}

@router.delete("/{scan_id}")
async def delete_single(
    scan_id: str,
    current_user=Depends(get_current_user),
    db=Depends(get_db),
):
    uid = str(current_user["_id"])
    await db.scans.delete_one({"_id": ObjectId(scan_id), "user_id": uid})
    return {"deleted": 1}