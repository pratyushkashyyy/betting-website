import sqlite3

from flask import g

def connect_to_database():
    sql = sqlite3.connect("betting.db")
    sql.row_factory = sqlite3.Row
    return sql

def get_database():
    if not hasattr(g, "betting_db"):
        g.betting_db = connect_to_database()
    return g.betting_db