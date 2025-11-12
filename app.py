import os
from datetime import datetime
from flask import (
    Flask, render_template, redirect, url_for,
    request, flash, send_from_directory, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from config import Config

# ------------------ APP CONFIG ------------------
app = Flask(__name__)
app.config.from_object(Config)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB
app.config.setdefault("DB_INIT_DONE", False)

# Ensure uploads folder exists (works locally & on Render)
UPLOAD_ROOT = app.config.get("UPLOAD_FOLDER", os.path.join(os.getcwd(), "uploads"))
os.makedirs(UPLOAD_ROOT, exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "docx", "txt"}

# ------------------ MODELS ------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="member")


class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey("folder.id"))
    uploaded_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    path = db.Column(db.String(255), nullable=False)

# ------------------ HELPERS ------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _ensure_db_initialized():
    """
    Safe to call multiple times. Creates tables and default admin if missing.
    We call this once on the first received request (works under Gunicorn/Render).
    """
    if app.config.get("DB_INIT_DONE"):
        return
    with app.app_context():
        db.create_all()
        # default admin
        if not User.query.filter_by(email="admin@local").first():
            hashed_pw = bcrypt.generate_password_hash("admin123").decode("utf-8")
            admin = User(
                name="Admin",
                email="admin@local",
                password_hash=hashed_pw,
                role="admin",
            )
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin account created: admin@local / admin123")
        app.config["DB_INIT_DONE"] = True
        print("✅ Database initialized and ready.")


# Call on every request until done (replacement for deprecated before_first_request)
@app.before_request
def _init_on_first_request():
    _ensure_db_initialized()


# ------------------ ROUTES ------------------
@app.route("/")
@login_required
def dashboard():
    folders = Folder.query.all()
    return render_template("dashboard.html", user=current_user, folders=folders)


@app.route("/folders/new", methods=["POST"])
@login_required
def create_folder():
    name = request.form.get("name")
    if name:
        folder = Folder(name=name, created_by=current_user.id)
        db.session.add(folder)
        db.session.commit()
        os.makedirs(os.path.join(UPLOAD_ROOT, name), exist_ok=True)
        flash("Folder created successfully!", "success")
    return redirect(url_for("dashboard"))


@app.route("/folders/<int:folder_id>")
@login_required
def view_folder(folder_id):
    folder = Folder.query.get_or_404(folder_id)
    files = File.query.filter_by(folder_id=folder.id).all()
    return render_template("files.html", folder=folder, files=files, user=current_user)


@app.route("/folders/<int:folder_id>/upload", methods=["POST"])
@login_required
def upload_file(folder_id):
    folder = Folder.query.get_or_404(folder_id)
    file = request.files.get("file")
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        folder_path = os.path.join(UPLOAD_ROOT, folder.name)
        os.makedirs(folder_path, exist_ok=True)
        file_path = os.path.join(folder_path, filename)
        file.save(file_path)

        new_file = File(
            filename=filename,
            folder_id=folder.id,
            uploaded_by=current_user.id,
            path=file_path,
        )
        db.session.add(new_file)
        db.session.commit()
        flash("File uploaded successfully!", "success")
    else:
        flash("Invalid file type!", "danger")
    return redirect(url_for("view_folder", folder_id=folder.id))


@app.route("/files/<int:file_id>/download")
@login_required
def download_file(file_id):
    f = File.query.get_or_404(file_id)
    folder = Folder.query.get(f.folder_id)
    folder_path = os.path.join(UPLOAD_ROOT, folder.name)
    return send_from_directory(folder_path, f.filename, as_attachment=True)


@app.route("/files/<int:file_id>/delete", methods=["POST"])
@login_required
def delete_file(file_id):
    f = File.query.get_or_404(file_id)
    if current_user.role != "admin":
        abort(403)
    if os.path.exists(f.path):
        os.remove(f.path)
    db.session.delete(f)
    db.session.commit()
    flash("File deleted!", "success")
    return redirect(url_for("view_folder", folder_id=f.folder_id))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.errorhandler(403)
def forbidden_error(e):
    return render_template("403.html"), 403


@app.errorhandler(404)
def not_found_error(e):
    return render_template("404.html"), 404


# ------------------ RUN LOCALLY ------------------
if __name__ == "__main__":
    # Local dev server; still ensures DB
    _ensure_db_initialized()
    app.run(host="0.0.0.0", port=5050, debug=True)
