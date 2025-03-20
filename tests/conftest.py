import pytest
from flask import Flask
from chatbot_flask.config import Config
from chatbot_flask.utils.logger import setup_logger

@pytest.fixture
def app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Setup logging
    setup_logger()
    
    # Register blueprints
    from chatbot_flask.routes import main, auth, admin
    app.register_blueprint(main.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(admin.bp)
    
    return app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def runner(app):
    return app.test_cli_runner()

@pytest.fixture
def auth_client(client):
    # Login and get session
    client.post('/auth/login', data={
        'email': 'test@example.com',
        'password': 'test123'
    })
    return client 