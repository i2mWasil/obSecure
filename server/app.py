# app.py - Updated version
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flask_migrate import Migrate
import os
from dotenv import load_dotenv

from config import config
from models import db
from routes.auth import auth_bp
from routes.keys import keys_bp

load_dotenv()

def create_app(config_name=None):
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Initialize extensions
    db.init_app(app)
    migrate = Migrate(app, db)

    # Rate limiting with fallback
    try:
        limiter = Limiter(
            key_func=get_remote_address,
            app=app,
            default_limits=["200 per day", "50 per hour"],
            storage_uri=app.config.get('RATELIMIT_STORAGE_URL')
        )
        print(f"✅ Rate limiter initialized with Redis: {app.config.get('RATELIMIT_STORAGE_URL')}")
    except Exception as e:
        print(f"⚠️  Redis connection failed, using memory storage: {e}")
        limiter = Limiter(
            key_func=get_remote_address,
            app=app,
            default_limits=["200 per day", "50 per hour"],
            storage_uri="memory://"
        )

    # CORS
    CORS(app, origins=app.config['CORS_ORIGINS'])

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api')
    app.register_blueprint(keys_bp, url_prefix='/api')

    # Health check endpoint
    @app.route('/health')
    def health_check():
        return {'status': 'OK', 'message': 'Server is running'}, 200

    # Error handlers
    @app.errorhandler(400)
    def bad_request(error):
        return {'error': 'Bad request'}, 400

    @app.errorhandler(404)
    def not_found(error):
        return {'error': 'Not found'}, 404

    @app.errorhandler(500)
    def internal_error(error):
        if hasattr(db, 'session'):
            db.session.rollback()
        return {'error': 'Internal server error'}, 500

    return app

if __name__ == '__main__':
    app = create_app()
    
    # Create tables if they don't exist
    with app.app_context():
        try:
            db.create_all()
            print("✅ Database tables created/verified")
        except Exception as e:
            print(f"⚠️  Database setup warning: {e}")
    
    print("🚀 Starting Flask server...")
    app.run(debug=True, host='0.0.0.0', port=5001)





