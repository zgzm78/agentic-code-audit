import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)

API_KEY = "demo-hardcoded-secret-value-12345"


@app.route("/user")
def user_lookup():
    user_id = request.args.get("id", "")
    conn = sqlite3.connect("demo.db")
    cursor = conn.cursor()
    cursor.execute("select * from users where id = " + user_id)
    return str(cursor.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return os.popen("ping -c 1 " + host).read()


@app.route("/download")
def download():
    name = request.args.get("name", "readme.txt")
    return open("files/" + name).read()
