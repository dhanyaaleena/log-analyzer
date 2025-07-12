import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Database configuration with PostgreSQL support
    DATABASE_URL = os.getenv('DATABASE_URL')
    if DATABASE_URL:
        # Use postgresql+psycopg2:// format for SQLAlchemy with PostgreSQL
        if DATABASE_URL.startswith('postgresql://'):
            # Convert to postgresql+psycopg2:// format
            DATABASE_URL = DATABASE_URL.replace('postgresql://', 'postgresql+psycopg2://', 1)
        SQLALCHEMY_DATABASE_URI = DATABASE_URL
    else:
        # Fallback to SQLite for development
        SQLALCHEMY_DATABASE_URI = 'sqlite:///app.db'
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-secret-key")  # never use weak key in prod

