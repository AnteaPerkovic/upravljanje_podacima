from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr, validator
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
import redis
import json
from passlib.context import CryptContext

import jwt
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi import APIRouter, Depends
from pydantic import EmailStr
import secrets
from fastapi import Request
from fastapi.security import OAuth2PasswordBearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from sqlalchemy import func


# Generira nasumičan 32-byte hex ključ
#print(secrets.token_hex(32))

from dotenv import load_dotenv
import os

# Učitaj varijable iz .env datoteke
load_dotenv()

# Dohvati SECRET_KEY iz .env datoteke
SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise ValueError("SECRET_KEY is not set in the environment variables")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Token ističe nakon 30 minuta



DATABASE_URL = "mysql+pymysql://root:db2025@localhost:3306/koncerti"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)

class Concert(Base):##
    __tablename__ = "concert"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(100), nullable=False)
    description = Column(String(255))

class City(Base):
    __tablename__ = "city"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    capacity = Column(Integer, nullable=False)

class Time(Base):
    __tablename__ = "time"
    id = Column(Integer, primary_key=True, index=True)
    concert_id = Column(Integer, ForeignKey("concert.id"), nullable=False)
    city_id = Column(Integer, ForeignKey("city.id"), nullable=False)
    time = Column(String(100), nullable=False)

    concert = relationship("Concert")
    city = relationship("City")

class Reservation(Base):
    __tablename__ = "reservations"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    time_id = Column(Integer, ForeignKey("time.id"), nullable=False)
    seats_reserved = Column(Integer, nullable=False)

    user = relationship("User")
    time = relationship("Time")

Base.metadata.create_all(bind=engine)

# Schemas
class UserCreate(BaseModel):
    email: str
    password: str

    @validator("password")
    def validate_password(cls, password):
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters long.")
        return password

class UserResponse(BaseModel):
    id: int
    email: str

    class Config:
        from_attributes = True

class ConcertCreate(BaseModel):
    title: str
    description: str | None = None

class ConcertResponse(BaseModel):
    id: int
    title: str
    description: str | None

    class Config:
        from_attributes = True

class CityCreate(BaseModel):
    name: str
    capacity: int

class CityResponse(BaseModel):
    id: int
    name: str
    capacity: int

    class Config:
        from_attributes = True

class TimeCreate(BaseModel):
    concert_id: int
    city_id: int
    time: str

class TimeResponse(BaseModel):
    id: int
    concert_id: int
    city_id: int
    time: str

    class Config:
        from_attributes = True

class ReservationCreate(BaseModel):
    time_id: int
    seats_reserved: int

class ReservationResponse(BaseModel):
    id: int
    user_id: int
    time_id: int
    seats_reserved: int

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str

app = FastAPI()



def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Autentifikacija korisnika
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == form_data.username).first()
    if not db_user or not verify_password(form_data.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials.")

    access_token = create_access_token(data={"sub": db_user.email, "is_admin": db_user.is_admin})
    return {"access_token": access_token, "token_type": "bearer"}



def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Utility functions

def hash_password(password: str) -> str:
    return password_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_context.verify(plain_password, hashed_password)

# FastAPI instance



router = APIRouter()

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    user = db.query(User).filter(User.email == payload["sub"]).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def is_admin(user: User):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Not enough privileges")

# User routes
@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered.")

    hashed_password = hash_password(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password, is_admin=False)  # Default is_admin = False
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.post("/login", response_model=Token)
def login_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials.")

    access_token = create_access_token(data={"sub": db_user.email, "is_admin": db_user.is_admin})
    return {"access_token": access_token, "token_type": "bearer"}

# Concert routes
@app.post("/concerts/", response_model=ConcertResponse)
def create_conect(concert: ConcertCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Not enough privileges")

    db_concert = Concert(title=concert.title, description=concert.description)
    db.add(db_concert)
    db.commit()
    db.refresh(db_concert)
    return db_concert

@app.get("/concerts/", response_model=list[ConcertResponse])
def list_concerts(db: Session = Depends(get_db)):
    cached_concerts = redis_client.get("concerts_cache")
    if cached_concerts:
        return json.loads(cached_concerts)

    db_concerts = db.query(Concert).all()
    concerts = [{"id": concert.id, "title": concert.title, "description": concert.description} for concert in db_concerts]
    redis_client.set("concerts_cache", json.dumps(concerts), ex=3600)
    return concerts

@app.get("/concerts/{concert_id}", response_model=ConcertResponse)
def get_concert(concert_id: int, db: Session = Depends(get_db)):
    db_concert = db.query(Concert).filter(Concert.id == concert_id).first()
    if not db_concert:
        raise HTTPException(status_code=404, detail="Concert not found")
    return db_concert

@app.put("/concerts/{concert_id}", response_model=ConcertResponse)
def update_concert(concert_id: int, concert: ConcertCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Not enough privileges")

    db_concert = db.query(Concert).filter(Concert.id == concert_id).first()
    if not db_concert:
        raise HTTPException(status_code=404, detail="Concert not found")

    db_concert.title = concert.title
    db_concert.description = concert.description
    db.commit()
    db.refresh(db_concert)
    redis_client.delete("concerts_cache")  # Opcionalno, za osvježavanje cache-a
    return db_concert

@app.delete("/concerts/{concert_id}")
def delete_concert(concert_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Not enough privileges")

    db_concert = db.query(Concert).filter(Concert.id == concert_id).first()
    if not db_concert:
        raise HTTPException(status_code=404, detail="Concert not found")

    db.delete(db_concert)
    db.commit()
    return {"message": "Concert deleted successfully"}

# City routes
@app.post("/citys/", response_model=CityResponse)
def create_city(city: CityCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Not enough privileges")

    db_city = City(name=city.name, capacity=city.capacity)
    db.add(db_city)
    db.commit()
    db.refresh(db_city)
    return db_city

@app.get("/citys/", response_model=list[CityResponse])
def list_citys(db: Session = Depends(get_db)):
    db_citys = db.query(City).all()
    return db_citys

@app.get("/citys/{city_id}", response_model=CityResponse)
def get_city(city_id: int, db: Session = Depends(get_db)):
    db_city = db.query(City).filter(City.id == city_id).first()
    if not db_city:
        raise HTTPException(status_code=404, detail="City not found")
    return db_city

@app.put("/citys/{city_id}", response_model=CityResponse)
def update_city(city_id: int, city: CityCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Not enough privileges")

    db_city = db.query(City).filter(City.id == city_id).first()
    if not db_city:
        raise HTTPException(status_code=404, detail="City not found")

    db_city.name = city.name
    db_city.capacity = city.capacity
    db.commit()
    db.refresh(db_city)
    return db_city


@app.delete("/citys/{city_id}")
def delete_city(city_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Not enough privileges")

    db_city = db.query(City).filter(City.id == city_id).first()
    if not db_city:
        raise HTTPException(status_code=404, detail="City not found")

    db.delete(db_city)
    db.commit()
    return {"message": "City deleted successfully"}


# Times routes
@app.post("/times/", response_model=TimeResponse)
def create_time(time: TimeCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Not enough privileges")

    db_time = Time(concert_id=time.concert_id, city_id=time.city_id, time=time.time)
    db.add(db_time)
    db.commit()
    db.refresh(db_time)
    return db_time


@app.get("/times/", response_model=list[TimeResponse])
def list_times(db: Session = Depends(get_db)):
    db_times = db.query(Time).all()
    return db_times

@app.get("/times/{time_id}", response_model=TimeResponse)
def get_time(time_id: int, db: Session = Depends(get_db)):
    db_time = db.query(Time).filter(Time.id == time_id).first()
    if not db_time:
        raise HTTPException(status_code=404, detail="Time not found")
    return db_time

@app.put("/times/{time_id}", response_model=TimeResponse)
def update_time(time_id: int, time: TimeCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Not enough privileges")

    db_time = db.query(Time).filter(Time.id == time_id).first()
    if not db_time:
        raise HTTPException(status_code=404, detail="Time not found")

    db_time.concert_id = time.concert_id
    db_time.city_id = time.city_id
    db_time.time = time.time
    db.commit()
    db.refresh(db_time)
    return db_time


@app.delete("/times/{time_id}")
def delete_time(time_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Not enough privileges")

    db_time = db.query(Time).filter(Time.id == time_id).first()
    if not db_time:
        raise HTTPException(status_code=404, detail="Time not found")

    db.delete(db_time)
    db.commit()
    return {"message": "Time deleted successfully"}


# Reservation routes
@app.post("/reservations/", response_model=ReservationResponse)
def create_reservation(
    reservation: ReservationCreate, 
    db: Session = Depends(get_db), 
    user: User = Depends(get_current_user)
):
    try:
        # Dohvat vremena i provjera postojanja
        db_time = db.query(Time).filter(Time.id == reservation.time_id).first()
        if not db_time:
            raise HTTPException(status_code=404, detail="Times not found.")

        # Dohvat dvorane povezane s vremenom
        db_city = db.query(City).filter(City.id == db_time.city_id).first()
        if not db_city:
            raise HTTPException(status_code=404, detail="City not found.")

        city_capacity = db_city.capacity
        print(f"City capacity: {city_capacity}")

        # Izračun zauzetih sjedala
        total_reserved_seats = (
            db.query(func.coalesce(func.sum(Reservation.seats_reserved), 0))
            .filter(Reservation.time_id == reservation.time_id)
            .scalar()
        )
        print(f"Total reserved seats: {total_reserved_seats}")

        # Provjera dostupnosti sjedala
        if total_reserved_seats + reservation.seats_reserved > city_capacity:
            raise HTTPException(status_code=400, detail="Not enough seats available.")

        # Kreiranje rezervacije
        db_reservation = Reservation(
            user_id=user.id,
            time_id=reservation.time_id,
            seats_reserved=reservation.seats_reserved,
        )
        db.add(db_reservation)
        db.commit()
        db.refresh(db_reservation)

        return db_reservation

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.get("/reservations/", response_model=list[ReservationResponse])
def list_reservations(db: Session = Depends(get_db)):
    db_reservations = db.query(Reservation).all()
    return db_reservations

@app.get("/reservations/{reservation_id}", response_model=ReservationResponse)
def get_reservation(reservation_id: int, db: Session = Depends(get_db)):
    db_reservation = db.query(Reservation).filter(Reservation.id == reservation_id).first()
    if not db_reservation:
        raise HTTPException(status_code=404, detail="Reservation not found")
    return db_reservation

@app.put("/reservations/{reservation_id}", response_model=ReservationResponse)
def update_reservation(
    reservation_id: int, 
    reservation: ReservationCreate, 
    db: Session = Depends(get_db), 
    user: User = Depends(get_current_user)  # Provjera trenutnog korisnika
):
    db_reservation = db.query(Reservation).filter(Reservation.id == reservation_id).first()
    if not db_reservation:
        raise HTTPException(status_code=404, detail="Reservation not found.")

    # Provjeriti ako korisnik pokušava ažurirati svoju rezervaciju
    if db_reservation.user_id != user.id:
        raise HTTPException(status_code=403, detail="You can only update your own reservations.")

    db_time = db.query(Time).filter(Time.id == reservation.time_id).first()
    if not db_time:
        raise HTTPException(status_code=404, detail="Time not found.")

    db_reservation.time_id = reservation.time_id
    db_reservation.seats_reserved = reservation.seats_reserved
    db.commit()
    db.refresh(db_reservation)
    return db_reservation


@app.delete("/reservations/{reservation_id}")
def delete_reservation(
    reservation_id: int, 
    db: Session = Depends(get_db), 
    user: User = Depends(get_current_user)  # Provjera trenutnog korisnika
):
    db_reservation = db.query(Reservation).filter(Reservation.id == reservation_id).first()
    if not db_reservation:
        raise HTTPException(status_code=404, detail="Reservation not found.")

    # Provjeriti ako korisnik pokušava obrisati svoju rezervaciju ili ako je administrator
    if db_reservation.user_id != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="You can only delete your own reservations or be an admin.")

    db.delete(db_reservation)
    db.commit()
    return {"message": "Reservation deleted successfully"}
