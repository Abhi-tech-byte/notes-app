import os

class Config:
    SECRET_KEY = "yoursecretkey"
    SQLALCHEMY_DATABASE_URI = "sqlite:///notes.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
