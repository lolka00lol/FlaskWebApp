from flask import Flask, render_template, request, redirect, url_for, session
from waitress import serve
import sqlite3
from flask_bcrypt import Bcrypt

app = Flask(
    __name__, template_folder="./app/templates", static_folder="./app/static"
)
app.secret_key = "very_secret_key"

# Add support for XSS vulnerabilities
app.jinja_env.autoescape = lambda template: False

bcrypt = Bcrypt(app)


def connect_db():
    return sqlite3.connect("main.db")


@app.route("/")
@app.route("/index")
def home():
    db = connect_db()
    cur = db.cursor()

    cur.execute(
        "SELECT news.*, users.id, users.username FROM news, users WHERE news.user_id = users.id"
    )
    news = cur.fetchall()

    cur.close()
    db.close()
    return render_template("pages/index.html", news=news)


@app.route("/contacts")
def contacts():
    return render_template("pages/contacts.html")


# NEWS
@app.route("/profile")
def profile():
    db = connect_db()
    cur = db.cursor()

    user_id = session["user_id"]

    if session["username"]:
        cur.execute("SELECT * FROM news WHERE user_id = ?", (user_id,))
        news = cur.fetchall()
    else:
        news = []

    cur.close()
    db.close()
    return render_template("pages/profile.html", news=news)


@app.route("/post/<news_id>", methods=["GET"])
def post(news_id):
    db = connect_db()
    cur = db.cursor()

    cur.execute(
        "SELECT news.*, users.id, users.username FROM news, users WHERE news.user_id = users.id AND news.id = ?",
        (news_id,),
    )
    news = cur.fetchall()

    cur.close()
    db.close()
    return render_template("pages/post.html", news=news)


# AUTH
@app.route("/auth", methods=["GET"])
def auth():
    return render_template("pages/auth.html")


# API
@app.route("/login", methods=["POST"])
def login():
    db = connect_db()
    username = request.form["username"]
    password = request.form["password"]

    cur = db.cursor()

    # SQL Injection - 2 | False Positive example
    # cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
    cur.execute(
        f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    )
    user = cur.fetchone()

    # if user and bcrypt.check_password_hash(
    #     password=password.encode(), pw_hash=user[2].encode()
    # ):
    if user:
        session["user_id"] = user[0]
        session["username"] = user[1]

        cur.close()
        db.close()
        return redirect(url_for("home"))

    cur.close()
    db.close()
    return "Login failed!", 401


@app.route("/register", methods=["POST"])
def register():
    db = connect_db()
    username = request.form["username"]
    password = request.form["password"]

    # If generate passwd hash and compare them, then SQL injection doesn't work
    # hashed_password = bcrypt.generate_password_hash(password.encode())

    cur = db.cursor()

    # SQL Injection - 1 | False Positive example
    try:
        cur.execute(
            # f"INSERT INTO users(username, password) VALUES ('{username}', '{hashed_password.decode()}')"
            f"INSERT INTO users(username, password) VALUES ('{username}', '{password}')"
        )
    except sqlite3.Error:
        cur.close()
        db.close()
        return "Try another username!", 409
    db.commit()

    cur.close()
    db.close()
    return redirect(url_for("home"))


@app.route("/update", methods=["POST"])
def update():
    db = connect_db()
    cur = db.cursor()

    user_id = session["user_id"]
    new_password = request.form["new_password"]
    # new_password_hashed = bcrypt.generate_password_hash(new_password.encode())

    if session["username"]:
        cur.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (
                # new_password_hashed.decode(),
                new_password,
                user_id,
            ),
        )
        cur.close()
        db.commit()
        db.close()
        return redirect(url_for("profile"))

    cur.close()
    db.close()
    return "Access denied", 401


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/delete_news/<news_id>", methods=["POST"])
def delete_news(news_id):
    db = connect_db()
    cur = db.cursor()

    if session["username"]:
        cur.execute("DELETE FROM news WHERE id = ?", (news_id,))
        cur.close()
        db.commit()
        db.close()
        return redirect(url_for("profile"))

    cur.close()
    db.close()
    return "Access denied", 401


# XSS Уязвимость - 2
@app.route("/add_news", methods=["POST"])
def add_news():
    db = connect_db()
    cur = db.cursor()

    user_id = session["user_id"]
    title = request.form["title"]
    imageURL = request.form["title_imageurl"]
    descNews = request.form["description"]

    if session["username"]:
        cur.execute(
            # XSS vulnerability | We can add ANYTHING in news!
            "INSERT INTO news(user_id, title, title_imageurl, description) VALUES (?, ?, ?, ?)",
            (user_id, title, imageURL, descNews),
        )
        cur.close()
        db.commit()
        db.close()
        return redirect(url_for("profile"))

    cur.close()
    db.close()
    return "Access denied", 401


if __name__ == "__main__":
    serve(app, host="0.0.0.0", port=5000)
