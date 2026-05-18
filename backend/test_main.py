"""Comprehensive API tests for the XorCrypt backend."""
import pytest


class TestAuthEndpoints:
    """Tests for authentication endpoints."""

    def test_preflight(self, client):
        """Test auth preflight endpoint."""
        response = client.post("/api/auth/preflight", json={"email": "new@example.com"})
        assert response.status_code == 200
        data = response.json()
        assert "auth_salt" in data

    def test_register_success(self, client):
        """Test successful user registration."""
        response = client.post(
            "/api/auth/register",
            json={
                "email": "newuser@example.com",
                "auth_hash": "test_hash_value",
                "registration_token": "test_token",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "newuser@example.com"

    def test_register_duplicate_email(self, client, registered_user):
        """Test registration with duplicate email fails."""
        response = client.post(
            "/api/auth/register",
            json={
                "email": registered_user["email"],
                "auth_hash": "different_hash",
                "registration_token": "test_token",
            },
        )
        assert response.status_code == 409

    def test_register_invalid_token(self, client):
        """Test registration with invalid token fails."""
        response = client.post(
            "/api/auth/register",
            json={
                "email": "newuser@example.com",
                "auth_hash": "test_hash",
                "registration_token": "invalid_token",
            },
        )
        assert response.status_code == 403

    def test_login_success(self, client, registered_user):
        """Test successful login."""
        response = client.post(
            "/api/auth/login",
            json={
                "email": registered_user["email"],
                "auth_hash": registered_user["auth_hash"],
            },
        )
        assert response.status_code == 200
        assert "sid" in client.cookies

    def test_login_wrong_auth_hash(self, client, registered_user):
        """Test login with wrong auth_hash fails."""
        response = client.post(
            "/api/auth/login",
            json={
                "email": registered_user["email"],
                "auth_hash": "wrong_hash",
            },
        )
        assert response.status_code == 401

    def test_login_nonexistent_user(self, client):
        """Test login with non-existent email fails."""
        response = client.post(
            "/api/auth/login",
            json={
                "email": "nonexistent@example.com",
                "auth_hash": "some_hash",
            },
        )
        assert response.status_code == 401

    def test_verify_password(self, client, logged_in_user):
        """Test password verification with auth_dep."""
        response = client.post(
            "/api/auth/verify",
            json={
                "email": logged_in_user["email"],
                "auth_hash": logged_in_user["auth_hash"],
            },
        )
        assert response.status_code == 200

    def test_me_authenticated(self, client, logged_in_user):
        """Test /me endpoint when authenticated."""
        response = client.get("/api/auth/me")
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == logged_in_user["email"]

    def test_me_unauthenticated(self, client):
        """Test /me endpoint without authentication."""
        response = client.get("/api/auth/me")
        assert response.status_code == 401

    def test_logout(self, client, logged_in_user):
        """Test logout endpoint."""
        response = client.post("/api/auth/logout")
        assert response.status_code == 200
        # After logout, /me should fail
        response = client.get("/api/auth/me")
        assert response.status_code == 401

    def test_change_password(self, client, logged_in_user):
        """Test password change."""
        new_hash = "new_auth_hash_value"
        response = client.post(
            "/api/auth/change-password",
            json={
                "email": logged_in_user["email"],
                "old_auth_hash": logged_in_user["auth_hash"],
                "new_auth_hash": new_hash,
            },
        )
        assert response.status_code == 200

    def test_change_password_wrong_old_hash(self, client, logged_in_user):
        """Test password change with wrong old hash fails."""
        response = client.post(
            "/api/auth/change-password",
            json={
                "email": logged_in_user["email"],
                "old_auth_hash": "wrong_hash",
                "new_auth_hash": "new_hash",
            },
        )
        assert response.status_code == 401


class TestVaultEndpoints:
    """Tests for vault item management."""

    def test_vault_list_empty(self, client, logged_in_user):
        """Test listing vault items when empty."""
        response = client.get("/api/vault")
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []

    def test_vault_create(self, client, logged_in_user):
        """Test creating a vault item."""
        response = client.post(
            "/api/vault",
            json={
                "email": logged_in_user["email"],
                "auth_hash": logged_in_user["auth_hash"],
                "label_ct": "encrypted_label",
                "payload_ct": "encrypted_payload",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert "id" in data
        item_id = data["id"]

        # Verify item was created
        response = client.get("/api/vault")
        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) == 1
        assert data["items"][0]["id"] == item_id

    def test_vault_update(self, client, logged_in_user):
        """Test updating a vault item."""
        # Create item
        create_response = client.post(
            "/api/vault",
            json={
                "email": logged_in_user["email"],
                "auth_hash": logged_in_user["auth_hash"],
                "label_ct": "original_label",
                "payload_ct": "original_payload",
            },
        )
        item_id = create_response.json()["id"]

        # Update item
        response = client.put(
            f"/api/vault/{item_id}",
            json={
                "email": logged_in_user["email"],
                "auth_hash": logged_in_user["auth_hash"],
                "label_ct": "updated_label",
                "payload_ct": "updated_payload",
            },
        )
        assert response.status_code == 200

    def test_vault_delete(self, client, logged_in_user):
        """Test deleting a vault item."""
        # Create item
        create_response = client.post(
            "/api/vault",
            json={
                "email": logged_in_user["email"],
                "auth_hash": logged_in_user["auth_hash"],
                "label_ct": "test_label",
                "payload_ct": "test_payload",
            },
        )
        item_id = create_response.json()["id"]

        # Delete item
        response = client.delete(
            f"/api/vault/{item_id}",
            json={
                "email": logged_in_user["email"],
                "auth_hash": logged_in_user["auth_hash"],
            },
        )
        assert response.status_code == 200

        # Verify deletion
        response = client.get("/api/vault")
        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) == 0


class TestHistoryEndpoints:
    """Tests for history management."""

    def test_history_list_empty(self, client, logged_in_user):
        """Test listing history when empty."""
        response = client.get("/api/history")
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []

    def test_history_add(self, client, logged_in_user):
        """Test adding to history."""
        response = client.post(
            "/api/history",
            json={
                "email": logged_in_user["email"],
                "auth_hash": logged_in_user["auth_hash"],
                "op": "viewed",
                "preview_ct": "encrypted_preview",
            },
        )
        assert response.status_code == 201

        # Verify history was added
        response = client.get("/api/history")
        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) == 1

    def test_history_delete_item(self, client, logged_in_user):
        """Test deleting a history item."""
        # Add history
        add_response = client.post(
            "/api/history",
            json={
                "email": logged_in_user["email"],
                "auth_hash": logged_in_user["auth_hash"],
                "op": "viewed",
                "preview_ct": "encrypted_preview",
            },
        )

        # Get history items to find the ID
        history_response = client.get("/api/history")
        history_id = history_response.json()["items"][0]["id"]

        # Delete the history item
        response = client.delete(
            f"/api/history/{history_id}",
            json={
                "email": logged_in_user["email"],
                "auth_hash": logged_in_user["auth_hash"],
            },
        )
        assert response.status_code == 200

    def test_history_clear(self, client, logged_in_user):
        """Test clearing all history."""
        # Add multiple history items
        for i in range(3):
            client.post(
                "/api/history",
                json={
                    "email": logged_in_user["email"],
                    "auth_hash": logged_in_user["auth_hash"],
                    "op": "viewed",
                    "preview_ct": f"preview_{i}",
                },
            )

        # Verify items were added
        response = client.get("/api/history")
        assert len(response.json()["items"]) == 3

        # Clear history
        response = client.delete(
            "/api/history",
            json={
                "email": logged_in_user["email"],
                "auth_hash": logged_in_user["auth_hash"],
            },
        )
        assert response.status_code == 200

        # Verify history is empty
        response = client.get("/api/history")
        assert len(response.json()["items"]) == 0


class TestSessionEndpoints:
    """Tests for session management."""

    def test_sessions_list(self, client, logged_in_user):
        """Test listing user sessions."""
        response = client.get("/api/sessions")
        assert response.status_code == 200
        data = response.json()
        assert "sessions" in data
        assert len(data["sessions"]) > 0

    def test_logout_all(self, client, logged_in_user):
        """Test logging out all sessions."""
        response = client.post(
            "/api/auth/logout-all",
            json={
                "email": logged_in_user["email"],
                "auth_hash": logged_in_user["auth_hash"],
            },
        )
        assert response.status_code == 200

        # Verify session is invalidated
        response = client.get("/api/auth/me")
        assert response.status_code == 401

    def test_login_history(self, client, logged_in_user):
        """Test retrieving login history."""
        response = client.get("/api/auth/logins")
        assert response.status_code == 200
        data = response.json()
        assert "logins" in data


class TestHealthEndpoint:
    """Tests for health check endpoint."""

    def test_health(self, client):
        """Test health check endpoint."""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"


class TestUnauthenticatedAccess:
    """Tests for endpoint access control."""

    def test_vault_requires_auth(self, client):
        """Test vault endpoints require authentication."""
        response = client.get("/api/vault")
        assert response.status_code == 401

    def test_history_requires_auth(self, client):
        """Test history endpoints require authentication."""
        response = client.get("/api/history")
        assert response.status_code == 401

    def test_sessions_requires_auth(self, client):
        """Test sessions endpoint requires authentication."""
        response = client.get("/api/sessions")
        assert response.status_code == 401

    def test_messages_requires_auth(self, client):
        """Test messages endpoints require authentication."""
        response = client.get("/api/messages")
        assert response.status_code == 401

    def test_groups_requires_auth(self, client):
        """Test groups endpoints require authentication."""
        response = client.get("/api/groups")
        assert response.status_code == 401
