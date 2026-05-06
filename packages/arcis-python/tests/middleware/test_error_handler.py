"""
ErrorHandler tests — covers production safety, sensitive info scrubbing, and framework handlers.
"""

from arcis.middleware.error_handler import ErrorHandler, create_error_handler, contains_sensitive_info


class TestContainsSensitiveInfo:
    """Test the sensitive pattern detection function."""

    def test_detects_sql_errors(self):
        assert contains_sensitive_info("SQLSTATE[42S02]: Base table not found")
        assert contains_sensitive_info("ORA-00942: table or view does not exist")
        assert contains_sensitive_info("SQLITE_ERROR: no such table: users")
        assert contains_sensitive_info('syntax error at or near "SELECT"')
        assert contains_sensitive_info('relation "users" does not exist')
        assert contains_sensitive_info('column "email" does not exist')
        assert contains_sensitive_info('duplicate key value violates unique constraint "users_pkey"')
        assert contains_sensitive_info("table users doesn't exist")
        assert contains_sensitive_info('unknown column "password" in field list')

    def test_detects_mongodb_errors(self):
        assert contains_sensitive_info("MongoError: E11000 duplicate key")
        assert contains_sensitive_info("MongoServerError: bad auth")
        assert contains_sensitive_info("MongoNetworkError: connection refused")
        assert contains_sensitive_info("E11000 duplicate key error")

    def test_detects_redis_errors(self):
        assert contains_sensitive_info("WRONGTYPE Operation against a key")
        assert contains_sensitive_info("ReplyError: CLUSTERDOWN")
        assert contains_sensitive_info("READONLY You can't write against a read only replica")

    def test_detects_connection_strings(self):
        assert contains_sensitive_info("Failed to connect to mongodb://admin:pass@10.0.0.1/db")
        assert contains_sensitive_info("postgres://user:pass@host/db")
        assert contains_sensitive_info("mysql://root@localhost/app")
        assert contains_sensitive_info("redis://default:pass@cache:6379")
        assert contains_sensitive_info("mongodb+srv://user:" + "pass@example.mongodb.net")

    def test_detects_python_tracebacks(self):
        assert contains_sensitive_info('File "/app/models/user.py", line 42')

    def test_detects_stack_traces(self):
        assert contains_sensitive_info("at UserService.findById (src/services/user.ts:42")

    def test_detects_internal_ips(self):
        assert contains_sensitive_info("Connection refused 127.0.0.1:5432")
        assert contains_sensitive_info("Timeout connecting to 10.0.1.55")
        assert contains_sensitive_info("ECONNREFUSED 192.168.1.100:3306")
        assert contains_sensitive_info("Failed at 172.16.0.5:27017")

    def test_does_not_flag_generic_messages(self):
        assert not contains_sensitive_info("Not found")
        assert not contains_sensitive_info("Invalid email format")
        assert not contains_sensitive_info("Rate limit exceeded")
        assert not contains_sensitive_info("Unauthorized")
        assert not contains_sensitive_info("Bad request")
        assert not contains_sensitive_info("Email already registered")


class TestErrorHandler:
    """Test ErrorHandler functionality."""

    def test_production_mode_hides_details(self):
        handler = ErrorHandler(is_dev=False)
        error = Exception("Database connection failed")
        response = handler.handle(error, status_code=500)

        assert response["error"] == "Internal Server Error"
        assert "stack" not in response
        assert "details" not in response

    def test_production_hides_5xx_by_default(self):
        handler = ErrorHandler(is_dev=False)
        error = Exception("Something went wrong internally")
        response = handler.handle(error, status_code=500)

        assert response["error"] == "Internal Server Error"
        assert "Something" not in response["error"]

    def test_production_hides_4xx_unless_exposed(self):
        """4xx errors should also be hidden unless explicitly exposed."""
        handler = ErrorHandler(is_dev=False)
        error = Exception("User admin@corp.com not found")
        response = handler.handle(error, status_code=404)

        assert response["error"] == "Internal Server Error"

    def test_production_shows_exposed_messages(self):
        handler = ErrorHandler(is_dev=False)
        error = Exception("Email already registered")
        response = handler.handle(error, status_code=409, expose=True)

        assert response["error"] == "Email already registered"

    def test_production_scrubs_db_errors_even_when_exposed(self):
        handler = ErrorHandler(is_dev=False)
        error = Exception('relation "users" does not exist')
        response = handler.handle(error, status_code=500, expose=True)

        assert response["error"] == "Internal Server Error"

    def test_production_scrubs_connection_strings_when_exposed(self):
        handler = ErrorHandler(is_dev=False)
        error = Exception("Failed to connect to mongodb://admin:secret@10.0.0.1:27017/prod")
        response = handler.handle(error, status_code=500, expose=True)

        assert response["error"] == "Internal Server Error"
        assert "mongodb://" not in str(response)
        assert "10.0.0.1" not in str(response)

    def test_development_mode_shows_details(self):
        handler = ErrorHandler(is_dev=True)
        error = Exception("Something broke")
        response = handler.handle(error, status_code=500)

        assert "details" in response
        assert "Something broke" in response["details"]

    def test_development_mode_shows_stack(self):
        handler = ErrorHandler(is_dev=True)
        try:
            raise ValueError("Test error")
        except ValueError as e:
            response = handler.handle(e, status_code=500)

        assert "stack" in response
        assert len(response["stack"]) > 0

    def test_development_shows_db_errors(self):
        """Dev mode should show full details even for sensitive errors."""
        handler = ErrorHandler(is_dev=True)
        error = Exception('relation "users" does not exist')
        response = handler.handle(error, status_code=500)

        assert "relation" in response["error"]
        assert "relation" in response["details"]

    def test_log_errors_default_true(self):
        handler = ErrorHandler(is_dev=False)
        assert handler.log_errors is True

    def test_log_errors_can_be_disabled(self):
        handler = ErrorHandler(is_dev=False, log_errors=False)
        # Should not raise even without a logger
        response = handler.handle(Exception("test"), status_code=500)
        assert response["error"] == "Internal Server Error"

    def test_custom_logger(self):
        logged = []

        class MockLogger:
            def error(self, msg, data):
                logged.append((msg, data))

        handler = ErrorHandler(is_dev=False, logger=MockLogger())
        handler.handle(Exception("test"), status_code=500)

        assert len(logged) == 1
        assert logged[0][0] == "Request error"
        assert logged[0][1]["error"] == "test"


class TestCreateErrorHandler:
    """Test the factory function."""

    def test_returns_error_handler(self):
        handler = create_error_handler(is_dev=False)
        assert isinstance(handler, ErrorHandler)

    def test_passes_options(self):
        handler = create_error_handler(is_dev=True, log_errors=False)
        assert handler.is_dev is True
        assert handler.log_errors is False

    def test_production_default(self):
        handler = create_error_handler()
        response = handler.handle(Exception("secret DB error"), status_code=500)
        assert response["error"] == "Internal Server Error"
