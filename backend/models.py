from app import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    files = db.relationship('LogFile', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class LogFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    entries = db.relationship('LogEntry', backref='logfile', lazy=True)

class LogEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    logfile_id = db.Column(db.Integer, db.ForeignKey('log_file.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    raw_line = db.Column(db.Text, nullable=False)
    parsed_data = db.Column(db.JSON, nullable=True)
    anomalies = db.relationship('Anomaly', backref='logentry', lazy=True)

class Anomaly(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    logentry_id = db.Column(db.Integer, db.ForeignKey('log_entry.id'), nullable=False)
    reason = db.Column(db.String(256), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    explanation = db.Column(db.Text, nullable=True)

class AnalysisResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('log_file.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    results = db.Column(db.JSON, nullable=False)
