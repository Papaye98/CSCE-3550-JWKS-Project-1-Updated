import pytest
from app import app
from jwk_manager import jwk_manager

@pytest.fixture
def client():
    # Ensure a new key is generated before each test
    if not jwk_manager.keys:
        jwk_manager.generate_key()

    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_jwks(client):
    response = client.get('/jwks')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['keys']) > 0  # Ensure keys are present

def test_auth(client):
    response = client.post('/auth')
    assert response.status_code == 200
    data = response.get_json()
    token = data['token']
    assert token  # Ensure a token is returned

def test_expired_auth(client):
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    data = response.get_json()
    token = data['token']
    assert token  # Ensure a token is returned even if expired
