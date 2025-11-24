import pytest
from app import app, hash_password, get_user
from unittest.mock import patch

# Flask test client
@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

# -------------------
# Test utility functions
# -------------------

def test_hash_password():
    password = "password123"
    hashed = hash_password(password)
    # MD5 of "password123"
    assert hashed == "482c811da5d5b4bc6d497ffa98491e38"

@patch("app.sqlite3.connect")
def test_get_user(mock_connect):
    mock_cursor = mock_connect.return_value.cursor.return_value
    mock_cursor.fetchone.return_value = ("alice", "hashedpass")
    
    result = get_user("alice")
    assert result == ("alice", "hashedpass")
    mock_cursor.execute.assert_called_once()  # SQL executed

# -------------------
# Test Flask routes
# -------------------

def test_login_success(client):
    with patch("app.get_user") as mock_get_user, patch("app.hash_password") as mock_hash:
        mock_get_user.return_value = ("alice", "hashedpass")
        mock_hash.return_value = "hashedpass"

        response = client.post("/login", data={"username": "alice", "password": "password123"})
        assert b"Login successful" in response.data

def test_login_failure(client):
    with patch("app.get_user") as mock_get_user, patch("app.hash_password") as mock_hash:
        mock_get_user.return_value = None
        mock_hash.return_value = "wronghash"

        response = client.post("/login", data={"username": "bob", "password": "password123"})
        assert b"Login failed" in response.data
