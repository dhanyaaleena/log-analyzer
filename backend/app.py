from flask import Flask
from flask_cors import CORS
from flask_migrate import Migrate
from config import Config
import os
from extensions import db, jwt

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Most permissive CORS for debugging
    CORS(app, origins=["http://localhost:3000"], supports_credentials=True, allow_headers="*")

    db.init_app(app)
    jwt.init_app(app)
    migrate = Migrate(app, db)

    # Import models so they are registered with SQLAlchemy
    from models import User, LogFile, LogEntry, Anomaly, AnalysisResult

    # Register blueprints
    from routes.auth import auth_bp
    from routes.upload import upload_bp
    from routes.analysis import analysis_bp
    app.register_blueprint(auth_bp, url_prefix='/log-analyzer/api/auth')
    app.register_blueprint(upload_bp, url_prefix='/log-analyzer/api/upload')
    app.register_blueprint(analysis_bp, url_prefix='/log-analyzer/api/analysis')

    # Create upload folder if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    @app.errorhandler(Exception)
    def handle_exception(e):
        import traceback
        print('--- Exception Occurred ---')
        traceback.print_exc()
        return {'error': str(e)}, 500

    @app.route('/log-analyzer/api/')
    def index():
        return {'status': 'Log Analyzer API running'}

    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(debug=True)
