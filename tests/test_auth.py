import pytest
from flask import session

def test_register(client):
    response = client.post('/auth/register', data={
        'email': 'test@example.com',
        'password': 'test123',
        'confirm_password': 'test123',
        'phone': '+1234567890'
    })
    assert response.status_code == 302
    assert response.location == '/auth/login'

def test_login(client):
    response = client.post('/auth/login', data={
        'email': 'test@example.com',
        'password': 'test123'
    })
    assert response.status_code == 302
    assert response.location == '/'
    assert session['user_id'] is not None

def test_logout(auth_client):
    response = auth_client.get('/auth/logout')
    assert response.status_code == 302
    assert response.location == '/'
    assert 'user_id' not in session

def test_email_verification(client):
    # First register a user
    client.post('/auth/register', data={
        'email': 'test@example.com',
        'password': 'test123',
        'confirm_password': 'test123',
        'phone': '+1234567890'
    })
    
    # Try to verify with invalid token
    response = client.get('/auth/verify-email/invalid-token')
    assert response.status_code == 400
    
    # Try to verify with valid token (mock)
    response = client.get('/auth/verify-email/valid-token')
    assert response.status_code == 302
    assert response.location == '/auth/login'

def test_phone_verification(auth_client):
    # Request phone verification
    response = auth_client.post('/auth/request-phone-verification')
    assert response.status_code == 200
    
    # Verify with invalid code
    response = auth_client.post('/auth/verify-phone', data={
        'verification_code': '000000'
    })
    assert response.status_code == 400
    
    # Verify with valid code (mock)
    response = auth_client.post('/auth/verify-phone', data={
        'verification_code': '123456'
    })
    assert response.status_code == 302
    assert response.location == '/' 