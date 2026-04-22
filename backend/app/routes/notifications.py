from fastapi import APIRouter

router = APIRouter()

@router.get("/")
def notifications_home():
    return {"msg": "notifications"}