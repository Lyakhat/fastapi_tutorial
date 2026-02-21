from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from urllib.parse import quote_plus


MYSQL_USER = "root"
MYSQL_PASSWORD = "Lya@1977"
MYSQL_HOST = "localhost"
MYSQL_PORT = "3306"
MYSQL_DATABASE = "fastapi"

DATABASE_URL = F"mysql+pymysql://{MYSQL_USER}:{quote_plus(MYSQL_PASSWORD)}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DATABASE}"

##CONNECTION
engine = create_engine(DATABASE_URL)

#SESSION
Sessionlocal = sessionmaker(autoflush=False, autocommit = False, bind=engine)

#STOP SESSION 
def get_db():
    db = Sessionlocal()
    try:
        yield db
    finally:
        db.close()

## Base
Base = declarative_base()
