import time
import secrets
import logging
from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from database import init_db, get_db, User, Task
from config import settings
from auth import (
    create_access_token, verify_password, get_password_hash, 
    oauth, store_auth_code, retrieve_auth_code
)
from datetime import datetime
from sqlalchemy import func

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize database
init_db()

app = FastAPI(title="FastAPI Google Auth")

# Rate Limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Session Middleware (needed for OAuth state)
app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== SCHEMAS ====================
from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class ExchangeRequest(BaseModel):
    code: str

class TaskCreate(BaseModel):
    user: str
    title: str
    description: str = None

class TaskUpdate(BaseModel):
    user: str = None
    title: str = None
    description: str = None

class TaskCreate(BaseModel):
    user: str
    title: str
    description: str = None

class TaskUpdate(BaseModel):
    user: str = None
    title: str = None
    description: str = None

# ==================== ROUTES ====================

@app.get("/api/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute("SELECT 1")
        db_status = "connected"
    except Exception:
        db_status = "disconnected"
    
    return {
        "status": "ok",
        "message": "API FastAPI funcionando correctamente",
        "database": db_status,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/register")
@limiter.limit("5/minute")
def register(request: Request, user_data: UserCreate, db: Session = Depends(get_db)):
    if len(user_data.username) < 3:
        raise HTTPException(status_code=400, detail="El username debe tener al menos 3 caracteres")
    if len(user_data.password) < 6:
        raise HTTPException(status_code=400, detail="La contraseña debe tener al menos 6 caracteres")
    
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(status_code=409, detail="El username ya existe")
    
    new_user = User(
        username=user_data.username,
        password_hash=get_password_hash(user_data.password),
        last_login=datetime.utcnow()
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    logger.info(f"Usuario registrado exitosamente: {new_user.username}")
    
    access_token = create_access_token(data={"sub": new_user.username})
    
    return {
        "message": "Usuario registrado exitosamente",
        "access_token": access_token,
        "user": new_user.to_dict()
    }

@app.post("/api/login")
@limiter.limit("10/minute")
def login(request: Request, login_data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == login_data.username).first()
    if not user or not verify_password(login_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Username o password inválidos")
    
    user.last_login = datetime.utcnow()
    db.commit()
    
    logger.info(f"Login exitoso: {user.username}")
    
    access_token = create_access_token(data={"sub": user.username})
    
    return {
        "message": "Login exitoso",
        "access_token": access_token,
        "user": user.to_dict()
    }

@app.get("/api/login/google")
async def google_login(request: Request):
    redirect_uri = request.url_for('authorize_google')
    # Generate state for CSRF protection (Authlib does this automatically if session is enabled)
    return await oauth.google.authorize_redirect(request, str(redirect_uri))

@app.get("/authorize/google")
async def authorize_google(request: Request, db: Session = Depends(get_db)):
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get('userinfo')
        if not user_info:
            user_info = await oauth.google.get('https://www.googleapis.com/oauth2/v3/userinfo', token=token)
            user_info = user_info.json()
            
        username = user_info.get('email')
        if not username:
             return RedirectResponse(url=f"{settings.cors_origins_list[0]}/auth/google/callback?error=no_email")
        
        user = db.query(User).filter(User.username == username).first()
        if not user:
            user = User(username=username, password_hash=None)
            db.add(user)
            db.commit()
            db.refresh(user)
            
        user.last_login = datetime.utcnow()
        db.commit()
        
        access_token = create_access_token(data={"sub": user.username})
        auth_code = secrets.token_urlsafe(24)
        store_auth_code(auth_code, access_token, user.to_dict())
        
        return RedirectResponse(url=f"{settings.cors_origins_list[0]}/auth/google/callback?code={auth_code}")
    except Exception as e:
        print(f"Error en autorización de Google: {e}")
        return RedirectResponse(url=f"{settings.cors_origins_list[0]}/auth/google/callback?error=auth_failed")

@app.post("/api/auth/google/exchange")
@limiter.limit("10/minute")
def exchange_google_code(request: Request, exchange_data: ExchangeRequest):
    code_data = retrieve_auth_code(exchange_data.code)
    if not code_data:
        raise HTTPException(status_code=401, detail="Código inválido o expirado")
    
    return {
        "message": "Autenticación con Google exitosa",
        "access_token": code_data['token'],
        "user": code_data['user']
    }

# Dependencies for protected routes
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

@app.get("/api/protected")
def protected(current_user: User = Depends(get_current_user)):
    return {
        "message": "Acceso autorizado",
        "user": current_user.to_dict()
    }

@app.get("/api/user/profile")
def get_profile(current_user: User = Depends(get_current_user)):
    return {
        "user": current_user.to_dict()
    }

@app.get("/api/stats")
def get_stats(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    total_users = db.query(User).count()
    from auth import auth_codes
    return {
        "total_users": total_users,
        "active_auth_codes": len(auth_codes),
        "timestamp": datetime.utcnow().isoformat()
    }

# ==================== TASK ROUTES ====================

@app.post("/api/tasks")
@limiter.limit("20/minute")
def create_task(request: Request, task_data: TaskCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if task_data.user != current_user.username:
        raise HTTPException(status_code=403, detail="No autorizado para crear tareas de otro usuario")
    
    new_task = Task(
        user=task_data.user,
        title=task_data.title,
        description=task_data.description
    )
    db.add(new_task)
    db.commit()
    db.refresh(new_task)
    return new_task.to_dict()

@app.get("/api/tasks")
def get_tasks(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    all_tasks = db.query(Task).all()
    return [task.to_dict() for task in all_tasks]

@app.get("/api/tasks/user/{user}")
def get_tasks_by_user(user: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user != current_user.username:
        raise HTTPException(status_code=403, detail="No autorizado para ver tareas de otro usuario")
    
    tasks = db.query(Task).filter(Task.user == user).all()
    return [task.to_dict() for task in tasks]

@app.get("/api/tasks/{task_id}")
def get_task_by_id(task_id: int, user: str = None, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    search_user = user or current_user.username
    task = db.query(Task).filter(Task.id == task_id, Task.user == search_user).first()
    
    if not task:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")
    
    if task.user != current_user.username:
        raise HTTPException(status_code=403, detail="No autorizado para ver esta tarea")
        
    return task.to_dict()

@app.put("/api/tasks/{task_id}")
@limiter.limit("20/minute")
def update_task(request: Request, task_id: int, task_data: TaskUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    task = db.query(Task).filter(Task.id == task_id).first()
    
    if not task:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")
    
    if task.user != current_user.username:
        raise HTTPException(status_code=403, detail="No autorizado para actualizar esta tarea")
    
    if task_data.user:
        task.user = task_data.user
    if task_data.title:
        task.title = task_data.title
    if task_data.description is not None:
        task.description = task_data.description
    
    db.commit()
    db.refresh(task)
    return task.to_dict()

@app.delete("/api/tasks/{task_id}")
@limiter.limit("20/minute")
def delete_task(request: Request, task_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    task = db.query(Task).filter(Task.id == task_id).first()
    
    if not task:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")
    
    if task.user != current_user.username:
        raise HTTPException(status_code=403, detail="No autorizado para eliminar esta tarea")
    
    db.delete(task)
    db.commit()
    return task.to_dict()

@app.delete("/api/tasks/user/{user}/deleteall")
@limiter.limit("5/minute")
def delete_all_tasks_by_user(request: Request, user: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user != current_user.username:
        raise HTTPException(status_code=403, detail="No autorizado para eliminar tareas de otro usuario")
    
    tasks = db.query(Task).filter(Task.user == user).all()
    if not tasks:
        return {"message": "No hay tareas para eliminar", "tasks": []}
    
    for task in tasks:
        db.delete(task)
    
    db.commit()
    return [task.to_dict() for task in tasks]

@app.get("/api/tasks/countsames/{user}")
def get_same_count(user: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user != current_user.username:
        raise HTTPException(status_code=403, detail="No autorizado")
    
    user_titles_query = db.query(Task.title).filter(Task.user == user).distinct()
    user_titles = [row[0] for row in user_titles_query.all()]
    
    if not user_titles:
        return {"message": "No tienes tareas creadas.", "results": []}
    
    query = db.query(
        func.count(func.distinct(Task.user)).label('Number of titles'),
        Task.title
    ).filter(
        Task.title.in_(user_titles),
        Task.user != user
    ).group_by(Task.title).all()
    
    if not query:
        return {"message": "Ningún título coincide con otros usuarios.", "results": []}
    
    result = [{'Number of titles': count, 'title': title} for count, title in query]
    return {"results": result}

@app.get("/api/tasks/countsame/{user}")
def get_same_title_email(user: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user != current_user.username:
        raise HTTPException(status_code=403, detail="No autorizado")
    
    user_titles_subquery = db.query(Task.title).filter(Task.user == user).subquery()
    
    tasks_with_same_titles = db.query(
        Task.title,
        Task.user
    ).filter(
        Task.title.in_(user_titles_subquery),
        Task.user != user
    ).all()
    
    if not tasks_with_same_titles:
        return {"message": "Ningún título coincide con otros usuarios.", "results": []}
    
    title_to_emails = {}
    for title, email in tasks_with_same_titles:
        if title not in title_to_emails:
            title_to_emails[title] = []
        if email not in title_to_emails[title]:
            title_to_emails[title].append(email)
    
    results = [{'title': title, 'emails': emails} for title, emails in title_to_emails.items()]
    return {"results": results}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
