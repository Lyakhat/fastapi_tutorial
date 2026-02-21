from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
import models, schemas, utils
from auth_database import get_db
from jose import jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordRequestForm


SECRET_KEY = "P1BLoxugz9Ic95UyNYJd3jQzrRgjBjKJc90bBZ1uQSA"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# helper function that takes user data
def create_access_token(data:dict):
    to_encode = data.copy()
    expire =  datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({'exp': expire})
    encode_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encode_jwt

app = FastAPI()

@app.post("/signup")
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # check user exit or not
    existing_user = db.query(models.User).filter(models.User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail= "Username already exist")


    # hash the password
    hashed_pass = utils.hash_password(user.password)

    #create new user instance
    new_user= models.User(
        username = user.username,
        email = user.email,
        hashed_password = hashed_pass,
        role = user.role
    )

    # Save user to databse
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    #return the value (excluding password)
    return {'id': new_user.id, "username": new_user.username, "email": new_user.email, "role": new_user.role}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db:Session = Depends(get_db)):    
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Username")
    
    if not utils.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Password")
    
    token_data = {'sub': user.username, 'role': user.role}
    token = create_access_token(token_data)
    return {"access_token": token, "token_type": "bearer"}