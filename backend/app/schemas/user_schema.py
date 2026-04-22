from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):

    name: str

    email: EmailStr

    password: str = Field(..., min_length=8)


class UserLogin(BaseModel):

    email: EmailStr

    password: str


class UserResponse(BaseModel):

    id: int

    name: str

    email: str