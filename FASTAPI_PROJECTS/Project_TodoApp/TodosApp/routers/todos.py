from fastapi import Depends, APIRouter
import models
from database import SessionLocal
from sqlalchemy.orm import Session
from typing import Annotated
from pydantic import BaseModel, Field
from models import Todos


router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

class Todo_Request(BaseModel):
    title: str = Field(min_length=3, max_length=15)
    description: str = Field(min_length=3, max_length=100)
    priority: int = Field(gt=0, lt=6)
    complete: bool = Field(default=False)

@router.get("/todos")
async def read_all_todos(db: db_dependency):
    return db.query(models.Todos).all()

@router.post("/create_todos")
async def create_user(db: db_dependency, todo_request: Todo_Request):
    todo_model = Todos(**todo_request.model_dump())
    db.add(todo_model)
    db.commit()