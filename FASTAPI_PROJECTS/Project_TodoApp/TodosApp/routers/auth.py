from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Path, status, HTTPException
from database import SessionLocal
from typing import Annotated
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, EmailStr
from models import Users
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt


router = APIRouter()

SECRET_KEY = "98819274e4eb47537d1629a161362f34219f1b59ca757d9d99c2e022e05060c0"
ALGORITHM = "HS256"

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
db_dependency = Annotated[Session, Depends(get_db)]

class User_Request(BaseModel):
    username: str = Field(min_length=3, max_length=10)
    email: EmailStr
    first_name: str = Field(min_length=3, max_length=10)
    last_name: str = Field(min_length=3, max_length=10)
    password: str = Field(min_length=5, max_length=10)
    is_active: bool = Field(default=True)
    role: str
    

class Token(BaseModel):
    access_token: str
    token_type: str
    
    
def authenticate_user(username: str, password: str, db):
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return user


def create_access_token(username: str, user_id: str, expires_delta: timedelta):
    
    encode = {"sub": username, "id": user_id}
    expires = datetime.utcnow() + expires_delta
    encode.update({"exp": expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)
      

@router.post("/auth", status_code=status.HTTP_201_CREATED)
async def create_User(db: db_dependency, user_request: User_Request):
    user_model = Users(
        username=user_request.username,
        email= user_request.email,
        first_name=user_request.first_name,
        last_name=user_request.last_name,
        hashed_password=bcrypt_context.hash(user_request.password),
        is_active=user_request.is_active,
        role=user_request.role
    )
    db.add(user_model)
    db.commit()
      
@router.post("/token", response_model=Token)
async def login_access_for_token(formdata: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
    user = authenticate_user(formdata.username, formdata.password, db)
    if not user:
        return {"Messege": "Authentication Failed"}
    token = create_access_token(user.username, user.id, timedelta(minutes=20))
    return {"access_token": token, "token_type": "bearer_token"}

@router.delete("/remove/user/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_user_by_id(db: db_dependency, user_id: int = Path(gt=0)):
    user = db.query(Users).filter(Users.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User Not Found")
    db.delete(user)
    db.commit()
    
    