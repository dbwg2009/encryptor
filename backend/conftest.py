"""Pytest configuration and shared fixtures for API testing."""
import os
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

os.environ["CIPHER_SECRET"] = "test_secret_key_32_bytes_long_1234"
os.environ["CIPHER_REGISTRATION_TOKEN"] = "test_token"


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        yield str(db_path)


@pytest.fixture
def app(temp_db):
    """Create FastAPI app with temporary database."""
    with patch.dict(os.environ, {"CIPHER_DB": temp_db}):
        from main import app, init_db
        init_db()
        yield app


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def registered_user(client):
    """Create and return a registered user."""
    email = "test@example.com"
    auth_hash = "test_auth_hash_value"

    response = client.post(
        "/api/auth/register",
        json={
            "email": email,
            "auth_hash": auth_hash,
            "registration_token": "test_token",
        },
    )
    assert response.status_code == 201
    return {"email": email, "auth_hash": auth_hash}


@pytest.fixture
def logged_in_user(client, registered_user):
    """Create a user and log them in, returning session cookies."""
    response = client.post(
        "/api/auth/login",
        json={
            "email": registered_user["email"],
            "auth_hash": registered_user["auth_hash"],
        },
    )
    assert response.status_code == 200

    return {
        "email": registered_user["email"],
        "auth_hash": registered_user["auth_hash"],
        "cookies": client.cookies,
    }
