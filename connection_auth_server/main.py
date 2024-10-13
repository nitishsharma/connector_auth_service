from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import uuid

# Secret key for encoding/decoding JWT tokens
SECRET_KEY = "your_super_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# In-memory "databases" (replace with real DB in production)
enterprise_db = {}
auth_db = {}
token_db = {}

# OAuth2 schemes
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Password context for hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pydantic models
class Enterprise(BaseModel):
    enterprise_id: str
    client_id: str
    client_secret: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    enterprise_id: str

app = FastAPI()

# Utility functions
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# Verify and decode JWT token
async def get_current_enterprise(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        enterprise_id: str = payload.get("sub")
        if enterprise_id is None:
            raise credentials_exception
        token_data = TokenData(enterprise_id=enterprise_id)
    except JWTError:
        raise credentials_exception
    return token_data

# API Endpoints
@app.post("/create-connector/", response_model=Enterprise)
async def create_connector(enterprise_id: str):
    """
    Create a new connector for an enterprise and return the client_id, client_secret.
    """
    if enterprise_id in enterprise_db:
        raise HTTPException(status_code=400, detail="Enterprise already exists")
    
    client_id = str(uuid.uuid4())
    client_secret = str(uuid.uuid4())  # In real use, this would be more secure and hashed
    hashed_secret = get_password_hash(client_secret)

    enterprise_db[enterprise_id] = {"client_id": client_id, "client_secret": hashed_secret}
    auth_db[client_id] = {"enterprise_id": enterprise_id, "client_secret": hashed_secret}

    return Enterprise(enterprise_id=enterprise_id, client_id=client_id, client_secret=client_secret)

@app.post("/token/", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 token endpoint. Authenticates client_id and client_secret, then returns an access token.
    """
    enterprise = auth_db.get(form_data.username)
    if not enterprise:
        raise HTTPException(status_code=401, detail="Invalid client_id")

    if not verify_password(form_data.password, enterprise["client_secret"]):
        raise HTTPException(status_code=401, detail="Invalid client_secret")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": enterprise["enterprise_id"]}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/session-info/")
async def get_session_info(current_enterprise: TokenData = Depends(get_current_enterprise)):
    """
    Retrieve session information for the authenticated enterprise.
    """
    enterprise_id = current_enterprise.enterprise_id
    if enterprise_id not in enterprise_db:
        raise HTTPException(status_code=404, detail="Enterprise not found")

    return {"enterprise_id": enterprise_id, "client_id": enterprise_db[enterprise_id]["client_id"]}

