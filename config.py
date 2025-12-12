import os

class Config: 
    # SECURITY:  Use strong secret key
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32).hex()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Database configuration (use environment variables in production)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'mysql+pymysql://coretally_app:Q9v!eF2pC7x#rUaL@localhost/app?charset=utf8mb4'
    )
    
    # MariaDB-optimized settings
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 280,
        'pool_size':  10,
        'max_overflow': 20,
        'connect_args': {
            'charset': 'utf8mb4',
            'connect_timeout':  10,
        }
    }
    
    # Application settings
    VAT_RATE = float(os.environ.get('VAT_RATE', 0.12))
    
    # Production mode (set to False for production)
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Session security
    SESSION_COOKIE_SECURE = False  # Set True if using HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour