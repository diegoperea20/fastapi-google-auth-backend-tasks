import bcrypt
from datetime import datetime, timedelta
from typing import Optional
from jose import jwt
from config import settings
from authlib.integrations.starlette_client import OAuth
from starlette.requests import Request

oauth = OAuth()
oauth.register(
    name='google',
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRET,
    server_metadata_url=settings.GOOGLE_DISCOVERY_URL,
    client_kwargs={'scope': 'openid profile email'}
)

def verify_password(plain_password, hashed_password):
    if not hashed_password:
        return False
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_password_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

# Auth code storage (mimicking Flask's in-memory storage)
auth_codes = {}

def _clean_expired_codes():
    """Limpia los códigos de autenticación expirados"""
    current_time = datetime.utcnow()
    expired_codes = [
        code for code, data in auth_codes.items()
        if data['expires_at'] < current_time
    ]
    for code in expired_codes:
        auth_codes.pop(code, None)

def store_auth_code(code, token, user_dict):
    _clean_expired_codes()
    expires_at = datetime.utcnow() + timedelta(minutes=5)
    auth_codes[code] = {
        'token': token,
        'user': user_dict,
        'expires_at': expires_at
    }

def retrieve_auth_code(code):
    if code not in auth_codes:
        return None
    
    code_data = auth_codes[code]
    if code_data['expires_at'] < datetime.utcnow():
        del auth_codes[code]
        return None
    
    del auth_codes[code]
    return code_data
