from sqlalchemy import create_engine

engine = create_engine("postgresql://postgres:<pwd>@localhost/postgres")
conn = engine.connect()
conn.execute("commit")
conn.execute("create database tanner")
conn.close()
