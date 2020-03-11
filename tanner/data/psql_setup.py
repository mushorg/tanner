from sqlalchemy import create_engine
engine=create_engine("postgresql://postgres:mark@2187@localhost/postgres")
conn=engine.connect()
conn.execute("commit")
conn.execute("create database tanner_db")
conn.close()
