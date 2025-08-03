import os
import sqlite3
import re
import uuid
from flask import Flask, flash, redirect, render_template, request, session, send_from_directory, g, make_response
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image

app = Flask(__name__)
app.secret_key = "your_secret_key_here"

def get_db():
    if 'db' not in g:
        db_path = "/app/potion.db"
        print("Using database at:", db_path)
        g.db = sqlite3.connect(db_path, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
        db = g.db  # ✅ Add this line
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                email TEXT UNIQUE,
                discord_id TEXT UNIQUE,
                profile_picture TEXT DEFAULT 'default_profile.png',
                bio TEXT,
                rank TEXT DEFAULT 'user',
                joined_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db:
        db.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("username") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def apology(message, code=400):
    def escape(s):
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ('"', "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        discord_id = request.form.get("discord_id")
        confirm_password = request.form.get("confirm_password")

        if not is_valid_email(email):
            return apology("Invalid email address!", 400)
        if len(password) < 8:
            return apology("Password must be at least 8 characters long!", 400)
        if password != confirm_password:
            return apology("Passwords do not match!", 400)
        if not username or not password or not email or not discord_id:
            return apology("All fields are required!", 400)

        try:
            db = get_db()
            hash_pw = generate_password_hash(password)
            db.execute("INSERT INTO users (username, password, email, discord_id) VALUES (?, ?, ?, ?)",
                       (username, hash_pw, email, discord_id))
            db.commit()
        except sqlite3.IntegrityError:
            return apology("Username, email or discord_id already exists!", 400)

        return redirect("/login")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        identifier = request.form.get("identifier")
        password = request.form.get("password")

        if not identifier or not password:
            return apology("All fields are required!", 400)

        user = get_db().execute(
            "SELECT * FROM users WHERE username = ? OR email = ? OR discord_id = ?",
            (identifier, identifier, identifier)
        ).fetchone()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect("/")
        else:
            return apology("Invalid credentials", 400)

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect("/login")

@app.route("/profile")
@login_required
def profile():
    user_id = session.get("user_id")
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return apology("User not found", 404)
    return render_template("profile.html", user=user)


@app.route("/upload_picture", methods=["POST"])
@login_required
def update_profile():
    file = request.files.get("profile_picture")

    if not file:
        return apology("No file uploaded", 400)

    filename = secure_filename(file.filename)
    ext = os.path.splitext(filename)[1].lower()

    # Validate allowed extensions
    allowed_extensions = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
    if ext not in allowed_extensions:
        return apology("Unsupported file type", 400)

    new_filename = str(uuid.uuid4()) + ext
    upload_path = os.path.join("static", "uploads", new_filename)

    # Open and resize image
    try:
        img = Image.open(file)
        img = img.convert("RGB") if ext in {".jpg", ".jpeg"} else img
        img = img.resize((150, 150))

        # Save with appropriate format
        img.save(upload_path, optimize=True, quality=60)
    except Exception as e:
        return apology(f"Image processing failed: {e}", 400)

    db = get_db()

    # Delete old profile picture if not default
    user = db.execute("SELECT profile_picture FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    old_picture = user["profile_picture"]

    if old_picture and old_picture != "default_profile.png":
        old_path = os.path.join("static", "uploads", old_picture)
        if os.path.exists(old_path):
            try:
                os.remove(old_path)
            except Exception as e:
                print(f"Could not delete old profile picture: {e}")

    # Update user record with new filename
    db.execute("UPDATE users SET profile_picture = ? WHERE id = ?", (new_filename, session["user_id"]))
    db.commit()

    flash("Profile picture updated successfully!")
    return redirect("/profile")

@app.route("/remove_picture", methods=["POST"])
@login_required
def remove_profile_picture():
    user_id = session.get("user_id")
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user or not user["profile_picture"]:
        return apology("No profile picture to remove", 400)

    # Delete the file
    if user["profile_picture"] != "default_profile.png":
        path = os.path.join("static", "uploads", user["profile_picture"])
        if os.path.exists(path):
            os.remove(path)

    db.execute("UPDATE users SET profile_picture = NULL WHERE id = ?", (user_id,))
    db.commit()

    flash("Profile picture removed successfully!")
    return redirect("/profile")

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    response = make_response(send_from_directory("static/uploads", filename))
    response.headers['Cache-Control'] = 'public, max-age=86400'
    return response

@app.route("/users")
@login_required
def users():
    users = get_db().execute("SELECT * FROM users").fetchall()
    return render_template("users.html", users=users)

@app.route("/profile/<int:user_id>")
@login_required
def user_profile(user_id):
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return apology("User not found", 404)
    return render_template("user_profile.html", user=user)

@app.after_request
def add_header(response):
    if "static/uploads" in request.path:
        response.headers["Cache-Control"] = "public, max-age=31536000"
    return response

@app.route("/update_bio", methods=["POST"])
@login_required
def update_bio():
    user_id = session.get("user_id")
    bio = request.form.get("bio")

    if not bio:
        return apology("Bio cannot be empty", 400)

    db = get_db()
    db.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, user_id))
    db.commit()

    flash("Bio updated successfully!")
    return redirect("/profile")

if __name__ == '__main__':
    app.run(debug=True)