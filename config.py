import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-full')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Prefer using an environment variable for the DB URI.
    # Example for pymysql: mysql+pymysql://user:pass@localhost/your_db?charset=utf8mb4
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'mysql+pymysql://coretally_app:Q9v!eF2pC7x#rUaL@localhost/app?charset=utf8mb4'
    )

    # Useful engine options for MySQL/MariaDB
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 280,
        # optionally set 'connect_args': {'charset': 'utf8mb4'}
    }

    # application config
    VAT_RATE = float(os.environ.get('VAT_RATE', 0.12))