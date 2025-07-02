from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
)
from waitress import serve
import sqlite3
from flask_bcrypt import Bcrypt
import sys

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

    # A03:2021 – Injection (SQL) 1 | Vulnerability 1
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


# A07:2021 – Identification and Authentication Failures | Vulnerability 4
@app.route("/register", methods=["POST"])
def register():
    db = connect_db()
    username = request.form["username"]
    password = request.form["password"]

    # If generate passwd hash and compare them, then SQL injection doesn't work
    # hashed_password = bcrypt.generate_password_hash(password.encode())

    cur = db.cursor()

    # A03:2021 – Injection (SQL) 2 | Vulnerability 1 (False Positive)
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


# A01:2021 – Broken Access Control (IDOR) | Vulnerability 3
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


# A7:2017 - Cross-Site Scripting (XSS) | Vulnerability 2
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


# Open redirects (A1:2021) | Vulnerability 5
@app.route("/redirect")
def open_redirect():
    target = request.args.get("url")
    if target:
        return redirect(target)
    return "No URL provided", 400


# ANY REQUESTS TO SQLITE DATABASE | VULNERABILITY TO DO ACTIONS WITHOUT ACCESS
@app.route("/sqlite", methods=["GET"])
def sqlite_query():
    query = request.args.get("query")
    if not query:
        return jsonify({"error": "Query parameter is required"}), 400

    db = connect_db()
    cur = db.cursor()

    try:
        cur.execute(query)

        # If query is start with SELECT command
        if query.strip().upper().startswith("SELECT"):
            row_headers = [x[0] for x in cur.description]
            rows = cur.fetchall()
            results = [dict(zip(row_headers, row)) for row in rows]

            cur.close()
            db.close()
            return jsonify(results), 200

        affected = cur.rowcount
        cur.close()
        db.commit()
        db.close()

        return (
            jsonify(
                {
                    "msg": f"Query successfully executed, affected rows: {affected}"
                }
            ),
            200,
        )
    except Exception as err:
        cur.close()
        db.close()
        return jsonify({"error": str(err)}), 500


if __name__ == "__main__":
    _host = "localhost"
    _port = 5000
    _debug = False
    args = sys.argv[1:]

    def help_menu() -> None:
        print(
            """
    My Shitty Flask Web App (MSFWA)!
=====================================
help, --help    | Show help menu (command)
resetdb         | !!!WARNING!!! RESETS DATABASE (command)
--test, -t      | Use command to test vuln in app
--testdb        | Add some test data in DB
--nonlocal, -nl | Listing all LAN Interfaces
--port <value>  | Use for custom port
=====================================\n"""
        )

    if len(args) > 0:
        if any(x in args for x in ["--help", "help"]):
            help_menu()
            exit(0)
        if not any(
            x in args
            for x in [
                "--test",
                "-t",
                "--nonlocal",
                "-nl",
                "--port",
                "--testdb",
                "resetdb",
            ]
        ):
            help_menu()
            exit(1)
        if "resetdb" in args:
            print("\nClean DATABASE")
            db = connect_db()
            cur = db.cursor()
            try:
                cur.execute("DELETE FROM users")
                cur.execute("DELETE FROM news")
                cur.execute("UPDATE sqlite_sequence SET seq=0")
                cur.close()
                db.commit()
                db.close()
            except Exception as err:
                print("Problem with reset DB, error:\n")
                print(err)
                cur.close()
                db.close()
                exit(1)
            print("Complete resetting DB!\n")
            exit(0)
        if any(x in args for x in ["--test", "-t"]):
            _debug = True
            args.append("--testdb")
        if "--testdb" in args:
            print("\nAdding new data in DATABASE")
            db = connect_db()
            cur = db.cursor()
            try:
                cur.execute(
                    "INSERT INTO users(username, password) VALUES ('Admin', 'P@ssw0rd')"
                )
                cur.execute(
                    "INSERT INTO news(user_id, title, title_imageurl, description) VALUES (1, 'Test XSS', 'https://cs13.pikabu.ru/post_img/2023/07/09/10/1688919144178579044.jpg', '<script>alert(`XSS?!`);</script>')"
                )
                cur.close()
                db.commit()
                db.close()
            except Exception as err:
                print("Problem with reset DB, error:\n")
                print(err)
                cur.close()
                db.close()
            print("Complete add data to DB!\n")
        if any(x in args for x in ["--nonlocal", "-nl"]):
            _host = "0.0.0.0"
        if "--port" in args:
            try:
                _port = int(args[args.index("--port") + 1])
            except Exception as err:
                print("Type error of port argument!\n")
                print(err)
    if _debug:
        print("\nDebug mode: True")
        app.run(host=_host, port=_port, debug=_debug)
        exit(0)
    else:
        print("\nDebug mode: False")
        serve(app, host=_host, port=_port)
        exit(0)
