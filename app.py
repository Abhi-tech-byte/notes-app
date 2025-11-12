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


class FolderAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    can_upload = db.Column(db.Boolean, default=False)
    can_view = db.Column(db.Boolean, default=True)


# ------------------ HELPERS ------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.context_processor
def inject_user():
    return dict(user=current_user)


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
        os.makedirs(os.path.join(app.config["UPLOAD_FOLDER"], name), exist_ok=True)
        flash("Folder created successfully!", "success")
    return redirect(url_for("dashboard"))


@app.route("/folders/<int:folder_id>")
@login_required
def view_folder(folder_id):
    folder = Folder.query.get_or_404(folder_id)

    # Everyone can view all folders (no restriction)
    files = File.query.filter_by(folder_id=folder.id).all()
    return render_template("files.html", folder=folder, files=files)


@app.route("/folders/<int:folder_id>/upload", methods=["POST"])
@login_required
def upload_file(folder_id):
    folder = Folder.query.get_or_404(folder_id)

    # All members can upload, but only admins can delete
    file = request.files.get("file")
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        folder_path = os.path.join(app.config["UPLOAD_FOLDER"], folder.name)
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
    file = File.query.get_or_404(file_id)
    folder = Folder.query.get(file.folder_id)
    folder_path = os.path.join(app.config["UPLOAD_FOLDER"], folder.name)
    return send_from_directory(folder_path, file.filename, as_attachment=True)


@app.route("/files/<int:file_id>/delete", methods=["POST"])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if current_user.role != "admin":
        abort(403)
    os.remove(file.path)
    db.session.delete(file)
    db.session.commit()
    flash("File deleted!", "success")
    return redirect(url_for("view_folder", folder_id=file.folder_id))


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


# ------------------ ADMIN PANEL ------------------
@app.route("/admin/users")
@login_required
def admin_users():
    if current_user.role != "admin":
        abort(403)
    users = User.query.all()
    folders = Folder.query.all()
    return render_template("admin_users.html", users=users, folders=folders)


@app.route("/admin/grant", methods=["POST"])
@login_required
def grant_access():
    if current_user.role != "admin":
        abort(403)

    user_id = request.form["user_id"]
    folder_id = request.form["folder_id"]
    can_upload = "can_upload" in request.form
    can_view = "can_view" in request.form

    existing = FolderAccess.query.filter_by(user_id=user_id, folder_id=folder_id).first()
    if existing:
        existing.can_upload = can_upload
        existing.can_view = can_view
    else:
        new_access = FolderAccess(
            user_id=user_id,
            folder_id=folder_id,
            can_upload=can_upload,
            can_view=can_view
        )
        db.session.add(new_access)
    db.session.commit()
    flash("Access updated!", "success")
    return redirect(url_for("admin_users"))


# ------------------ ADMIN: ADD USER ------------------
@app.route("/admin/add_user", methods=["GET", "POST"])
@login_required
def add_user():
    if current_user.role != "admin":
        abort(403)

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        role = request.form["role"]

        if User.query.filter_by(email=email).first():
            flash("User with that email already exists!", "danger")
            return redirect(url_for("add_user"))

        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(name=name, email=email, password_hash=hashed_pw, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash("User created successfully!", "success")
        return redirect(url_for("admin_users"))

    return render_template("add_user.html")


# ------------------ DB INIT ------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        if not User.query.first():
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

    app.run(host="0.0.0.0",debug=True, port=5050)
