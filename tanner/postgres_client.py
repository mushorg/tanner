import sqlalchemy import create_engine
from tanner.config import TannerConfig

class Postgressclient:
    host=TannerConfig.get('POSTGRES', 'host')
    port=TannerConfig.get('POSTGRES', 'port')
    dbname=TannerConfig.get('POSTGRES', 'db_name')
    user=TannerConfig.get('POSTGRES', 'user')
    password=TannerConfig.get('POSTGRES', 'password')
    db_string="postgresql://{}:{}@{}:{}/{}".format(user, password, host, port, dbname)
    db = create_engine(db_string)
