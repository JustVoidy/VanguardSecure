from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from app.database import get_db
from app.models.user import User
from app.utils.jwt_utils import verify_token

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class ProfileUpdate(BaseModel):
    name: str
    phone: str = ""
    location: str = ""
    twoFA: bool = True
    alerts: bool = True
    reports: bool = False


class PasswordUpdate(BaseModel):
    new_password: str


@router.get("/")
def get_profile(claims: dict = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == claims["sub"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "name":      user.name,
        "email":     user.email,
        "role":      "Administrator",
        "joined":    "2024",
        "last_login": "recently",
    }


@router.post("/update")
def update_profile(data: ProfileUpdate, claims: dict = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == claims["sub"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.name = data.name
    db.commit()
    return {"message": "profile updated", "name": user.name, "email": user.email}


@router.post("/update-password")
def update_password(data: PasswordUpdate, claims: dict = Depends(verify_token), db: Session = Depends(get_db)):
    if len(data.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    user = db.query(User).filter(User.email == claims["sub"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.password = pwd_context.hash(data.new_password)
    db.commit()
    return {"message": "password updated"}
