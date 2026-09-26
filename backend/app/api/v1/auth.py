"""Auth: POST /auth/login, GET /auth/me (api.md §4)."""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.core import config as cfg
from app.core import security as sec

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginBody(BaseModel):
    email: str
    password: str


@router.post("/login")
def login(body: LoginBody):
    user = sec.authenticate(body.email, body.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return cfg.ok(sec.make_token(user), "Login successful")


@router.get("/me")
def me(user=Depends(sec.get_current_user)):
    return cfg.ok({"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"]})
