#!/bin/bash

# Wait for database to be ready
echo "Waiting for database to be ready..."
python -c "
import time
import psycopg2
from config import Config

while True:
    try:
        conn = psycopg2.connect(
            host='postgres',
            port=5432,
            database='loganalyzerdb',
            user='dbuser',
            password='db123456'
        )
        conn.close()
        print('Database is ready!')
        break
    except psycopg2.OperationalError:
        print('Database not ready, waiting...')
        time.sleep(2)
"

# Initialize database
echo "Initializing database..."
python -c "
from app import app
from extensions import db
from models import User

app.app_context().push()

# Create all tables
db.create_all()
print('Database tables created successfully')

# Create default user if it doesn't exist
if not User.query.filter_by(username='admin').first():
    user = User(username='admin')
    user.set_password('admin123')
    db.session.add(user)
    db.session.commit()
    print('Default user created: username=admin, password=admin123')
else:
    print('Default user already exists')
"

# Start the application
exec gunicorn -c gunicorn_config.py app:app 