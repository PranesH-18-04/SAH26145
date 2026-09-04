from fastapi import APIRouter
from services.database import get_history

router = APIRouter()

@router.get("/")
async def get_traffic_history(limit: int = 100):
    return get_history(limit)
