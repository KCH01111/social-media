from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional
import bcrypt
import jwt
import datetime
from elasticsearch import ConflictError
from configurations import (
    JWT_SECRET,
    JWT_CONFIG,
    PASSWORD_CONFIG,
    USERNAME_CONFIG,
    ES_CONFIG,
    ERROR_MESSAGES
)

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# --- Models ---
class User(BaseModel):
    username: str
    password_hash: str
    is_active: bool = True
    role: str = ES_CONFIG["default_role"]

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

class UserCreate(BaseModel):
    username: str
    password: str

# --- Helper Functions (Same as Tornado) ---
def verify_jwt_token(token: str) -> Optional[dict]:
    """Identical to your Tornado version"""
    try:
        return jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_CONFIG["algorithm"]],
            options={
                "require": JWT_CONFIG["required_claims"],
                "verify_exp": True,
                "verify_iat": True
            },
            issuer=JWT_CONFIG["issuer"]
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES["invalid_token"]
        )

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """Replaces @jwt_required decorator with DI"""
    payload = verify_jwt_token(token)
    return {"user_id": payload["sub"], "username": payload["username"]}

# --- Routes ---
@app.post("/register", status_code=201)
async def register(user_data: UserCreate):
    # Validation
    if not USERNAME_CONFIG["regex"].match(user_data.username):
        raise HTTPException(400, detail=ERROR_MESSAGES["validation_error"]["username"])
    
    if not (PASSWORD_CONFIG["min_length"] <= len(user_data.password) <= PASSWORD_CONFIG["max_length"]):
        raise HTTPException(400, detail=ERROR_MESSAGES["validation_error"]["password"])

    # Check if user exists
    if es.exists(index=ES_CONFIG["user_index"], id=user_data.username):
        raise HTTPException(409, detail=ERROR_MESSAGES["username_taken"])

    # Create user (same hash logic as Tornado)
    hashed_pw = bcrypt.hashpw(user_data.password.encode(), bcrypt.gensalt(PASSWORD_CONFIG["bcrypt_rounds"]))
    user_doc = {
        "username": user_data.username,
        "password_hash": hashed_pw.decode(),
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "is_active": True,
        "role": ES_CONFIG["default_role"]
    }
    
    es.index(index=ES_CONFIG["user_index"], id=user_data.username, document=user_doc)
    return {"message": "User registered"}

@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Authenticate
    try:
        user_doc = es.get(index=ES_CONFIG["user_index"], id=form_data.username)["_source"]
    except:
        raise HTTPException(401, detail=ERROR_MESSAGES["invalid_credentials"])

    if not bcrypt.checkpw(form_data.password.encode(), user_doc["password_hash"].encode()):
        raise HTTPException(401, detail=ERROR_MESSAGES["invalid_credentials"])

    # Generate token (same as Tornado)
    token_data = _generate_jwt_token(user_doc["username"], user_doc["username"])
    return {
        "access_token": token_data["token"],
        "token_type": "Bearer",
        "expires_in": token_data["expires_in"]
    }

@app.get("/me")
async def read_me(current_user: dict = Depends(get_current_user)):
    return current_user