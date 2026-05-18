# API Test Suite

Comprehensive testing setup for the XorCrypt FastAPI backend.

## Setup

### Install Test Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### Run Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest test_main.py

# Run specific test class
pytest test_main.py::TestAuthEndpoints

# Run specific test
pytest test_main.py::TestAuthEndpoints::test_login_success

# Run with coverage report
pytest --cov=. --cov-report=html
```

## Test Structure

### conftest.py
Shared test fixtures and configuration:
- `temp_db`: Temporary database for isolated tests
- `app`: FastAPI application instance
- `client`: Test client for making HTTP requests
- `registered_user`: Pre-created user account
- `logged_in_user`: User logged in with valid session

### test_main.py
Comprehensive test cases organized by endpoint category:

#### TestAuthEndpoints
- Registration (success, duplicate email, invalid token)
- Login (success, wrong hash, non-existent user)
- Password verification
- User info retrieval (/me)
- Logout and logout-all
- Password change
- Login history

#### TestVaultEndpoints
- Create vault items
- List vault items
- Update vault items
- Delete vault items

#### TestHistoryEndpoints
- List history
- Add to history
- Delete individual history items
- Clear all history

#### TestSessionEndpoints
- List active sessions
- Logout all sessions
- View login history

#### TestHealthEndpoint
- Health check endpoint

#### TestUnauthenticatedAccess
- Verify authentication is required for protected endpoints

## Key Testing Features

- **Database Isolation**: Each test runs with a temporary database
- **Session Management**: Fixtures handle user registration and login
- **CSRF Protection**: Tests work with CSRF token handling
- **Error Cases**: Tests cover both success and failure scenarios
- **Authentication**: Tests verify access control for protected endpoints

## Adding New Tests

1. Add test methods to appropriate test class or create new class
2. Use fixtures from `conftest.py` (client, registered_user, logged_in_user)
3. Follow naming convention: `test_<endpoint>_<scenario>`
4. Include docstring explaining what is being tested
5. Assert both status codes and response data

Example:
```python
def test_new_endpoint(self, client, logged_in_user):
    """Test description."""
    response = client.get("/api/endpoint")
    assert response.status_code == 200
    assert response.json()["key"] == "expected_value"
```

## Environment Variables

Tests use these environment variables (set in conftest.py):
- `CIPHER_SECRET`: Test secret key for cryptography
- `CIPHER_REGISTRATION_TOKEN`: Test token for user registration
- `CIPHER_DB`: Temporary database path (auto-configured per test)
