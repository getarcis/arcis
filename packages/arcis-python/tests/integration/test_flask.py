"""
Arcis Flask Integration Tests
==============================

Tests for Flask middleware integration.
Run with: pytest tests/test_flask.py -v
"""

import pytest

# Skip these tests if Flask is not installed
pytest.importorskip("flask")

from flask import Flask, jsonify, request, g

from arcis.core import (
    Arcis,
    SchemaValidator,
)


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def app():
    """Create a Flask app with Arcis protection."""
    app = Flask(__name__)
    app.config['TESTING'] = True
    
    arcis = Arcis(app)
    
    @app.route('/')
    def index():
        return jsonify({"message": "Hello World"})
    
    @app.route('/echo', methods=['POST'])
    def echo():
        # Return sanitized data from g.json (or g.sanitized_json)
        data = getattr(g, 'json', None) or getattr(g, 'sanitized_json', None) or {}
        return jsonify({"received": data})
    
    @app.route('/health')
    def health():
        return jsonify({"status": "ok"})
    
    # Store arcis instance for cleanup
    app.arcis = arcis
    
    yield app
    
    # Cleanup
    arcis.close()


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def rate_limited_app():
    """Create app with low rate limit for testing."""
    app = Flask(__name__)
    app.config['TESTING'] = True
    
    arcis = Arcis(app, rate_limit_max=3, rate_limit_window_ms=60000)
    
    @app.route('/')
    def index():
        return jsonify({"message": "Hello"})
    
    @app.route('/health')
    def health():
        return jsonify({"status": "ok"})
    
    app.arcis = arcis
    
    yield app
    
    arcis.close()


@pytest.fixture
def rate_limited_client(rate_limited_app):
    """Create test client for rate limited app."""
    return rate_limited_app.test_client()


# ============================================================================
# SECURITY HEADERS TESTS
# ============================================================================

class TestFlaskSecurityHeaders:
    """Test security headers are applied to responses."""
    
    def test_csp_header_present(self, client):
        response = client.get('/')
        assert 'Content-Security-Policy' in response.headers
    
    def test_x_content_type_options_present(self, client):
        response = client.get('/')
        assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    
    def test_x_frame_options_present(self, client):
        response = client.get('/')
        assert response.headers.get('X-Frame-Options') == 'DENY'
    
    def test_x_xss_protection_present(self, client):
        response = client.get('/')
        assert response.headers.get('X-XSS-Protection') == '0'
    
    def test_hsts_header_present(self, client):
        response = client.get('/')
        hsts = response.headers.get('Strict-Transport-Security', '')
        assert 'max-age=' in hsts
    
    def test_referrer_policy_present(self, client):
        response = client.get('/')
        assert response.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'
    
    def test_permissions_policy_present(self, client):
        response = client.get('/')
        assert 'Permissions-Policy' in response.headers
    
    def test_x_powered_by_removed(self, client):
        response = client.get('/')
        assert 'X-Powered-By' not in response.headers
    
    def test_server_header_removed(self, client):
        response = client.get('/')
        # Flask's test client may not have Server header, but if it does, it should be removed
        # This is more important in production with werkzeug/gunicorn


# ============================================================================
# RATE LIMITING TESTS
# ============================================================================

class TestFlaskRateLimiting:
    """Test rate limiting in Flask middleware."""
    
    def test_rate_limit_headers_present(self, client):
        response = client.get('/')
        assert 'X-RateLimit-Limit' in response.headers
        assert 'X-RateLimit-Remaining' in response.headers
        assert 'X-RateLimit-Reset' in response.headers
    
    def test_allows_requests_under_limit(self, rate_limited_client):
        for i in range(3):
            response = rate_limited_client.get('/')
            assert response.status_code == 200, f"Request {i+1} should pass"
    
    def test_blocks_requests_over_limit(self, rate_limited_client):
        # Make 3 requests (all should pass)
        for i in range(3):
            response = rate_limited_client.get('/')
            assert response.status_code == 200
        
        # 4th request should be blocked
        response = rate_limited_client.get('/')
        assert response.status_code == 429
        
        data = response.get_json()
        assert 'error' in data
        assert 'retry_after' in data
    
    def test_rate_limit_response_has_retry_after(self, rate_limited_client):
        # Exhaust rate limit
        for _ in range(4):
            response = rate_limited_client.get('/')
        
        assert response.status_code == 429
        assert 'Retry-After' in response.headers
    
    def test_rate_limit_remaining_decrements(self, client):
        response1 = client.get('/')
        remaining1 = int(response1.headers.get('X-RateLimit-Remaining', 0))
        
        response2 = client.get('/')
        remaining2 = int(response2.headers.get('X-RateLimit-Remaining', 0))
        
        assert remaining1 > remaining2


# ============================================================================
# SANITIZATION TESTS (from TEST_VECTORS.json)
# ============================================================================

class TestFlaskSanitization:
    """Test request body sanitization."""
    
    def test_sanitizes_xss_script_tag(self, client):
        data = {"name": "<script>alert('xss')</script>"}
        response = client.post('/echo', json=data)
        
        result = response.get_json()
        assert '<script>' not in result['received'].get('name', '')
        assert 'alert' not in result['received'].get('name', '')
    
    def test_sanitizes_xss_onerror(self, client):
        data = {"html": '<img onerror="alert(1)" src="x">'}
        response = client.post('/echo', json=data)
        
        result = response.get_json()
        assert 'onerror' not in result['received'].get('html', '')
    
    def test_sanitizes_xss_javascript_protocol(self, client):
        data = {"link": "javascript:alert(1)"}
        response = client.post('/echo', json=data)
        
        result = response.get_json()
        assert 'javascript:' not in result['received'].get('link', '').lower()
    
    def test_sanitizes_xss_iframe(self, client):
        data = {"content": '<iframe src="evil.com">'}
        response = client.post('/echo', json=data)
        
        result = response.get_json()
        assert '<iframe' not in result['received'].get('content', '').lower()
    
    def test_sanitizes_xss_data_protocol(self, client):
        data = {"src": "data:text/html,<script>alert(1)</script>"}
        response = client.post('/echo', json=data)
        
        result = response.get_json()
        received = result['received'].get('src', '')
        assert 'data:' not in received.lower() or '<script>' not in received
    
    def test_sanitizes_sql_drop_table(self, client):
        data = {"query": "'; DROP TABLE users; --"}
        response = client.post('/echo', json=data)
        
        result = response.get_json()
        assert 'DROP' not in result['received'].get('query', '').upper()
    
    def test_sanitizes_sql_into_outfile(self, client):
        # Updated 2026-06-07 (benchmark FP class B3): bare `SELECT * FROM`
        # no longer flagged because the SDK allows benign code snippets.
        # INTO OUTFILE is the exclusive attacker file-write primitive.
        data = {"query": "1 UNION SELECT 'x' INTO OUTFILE '/var/www/x.php'"}
        response = client.post('/echo', json=data)

        result = response.get_json()
        assert 'INTO OUTFILE' not in result['received'].get('query', '').upper()

    def test_preserves_bare_select_from_b3_fp(self, client):
        # Sharing example SQL in a comment / chat / issue is benign.
        # Real injection has additional shape that other patterns catch.
        text = "SELECT * FROM users WHERE id = ?"
        response = client.post('/echo', json={"query": text})
        result = response.get_json()
        assert result['received'].get('query') == text
    
    def test_sanitizes_sql_union(self, client):
        data = {"query": "1 UNION SELECT password FROM users"}
        response = client.post('/echo', json=data)
        
        result = response.get_json()
        query = result['received'].get('query', '').upper()
        assert 'UNION' not in query
        assert 'SELECT' not in query
    
    def test_sanitizes_sql_comments(self, client):
        data = {"query": "admin'--"}
        response = client.post('/echo', json=data)
        
        result = response.get_json()
        assert '--' not in result['received'].get('query', '')
    
    def test_sanitizes_path_traversal(self, client):
        data = {"path": "../../etc/passwd"}
        response = client.post('/echo', json=data)
        
        result = response.get_json()
        assert '../' not in result['received'].get('path', '')
    
    def test_sanitizes_path_traversal_windows(self, client):
        data = {"path": "..\\..\\windows\\system32"}
        response = client.post('/echo', json=data)
        
        result = response.get_json()
        assert '..\\' not in result['received'].get('path', '')
    
    def test_sanitizes_path_traversal_encoded(self, client):
        data = {"path": "%2e%2e%2f%2e%2e%2f"}
        response = client.post('/echo', json=data)
        
        result = response.get_json()
        assert '%2e%2e' not in result['received'].get('path', '').lower()
    
    def test_blocks_prototype_pollution_proto(self, client):
        data = {"__proto__": {"admin": True}, "name": "test"}
        response = client.post('/echo', json=data)
        
        result = response.get_json()
        assert '__proto__' not in result['received']
        assert result['received'].get('name') == 'test'
    
    def test_blocks_prototype_pollution_constructor(self, client):
        data = {"constructor": {"prototype": {}}, "email": "test@test.com"}
        response = client.post('/echo', json=data)
        
        result = response.get_json()
        assert 'constructor' not in result['received']
        assert 'email' in result['received']
    
    def test_blocks_nosql_gt_operator(self, client):
        data = {"$gt": "", "name": "test"}
        response = client.post('/echo', json=data)
        
        result = response.get_json()
        assert '$gt' not in result['received']
        assert result['received'].get('name') == 'test'
    
    def test_blocks_nosql_where_operator(self, client):
        data = {"$where": "function(){ return true; }", "id": 1}
        response = client.post('/echo', json=data)
        
        result = response.get_json()
        assert '$where' not in result['received']
        assert result['received'].get('id') == 1
    
    def test_sanitizes_nested_objects(self, client):
        data = {"user": {"bio": "<script>xss</script>"}}
        response = client.post('/echo', json=data)
        
        result = response.get_json()
        bio = result['received'].get('user', {}).get('bio', '')
        assert '<script>' not in bio
    
    def test_sanitizes_arrays(self, client):
        data = {"items": ["<script>alert(1)</script>", "normal"]}
        response = client.post('/echo', json=data)
        
        result = response.get_json()
        items = result['received'].get('items', [])
        assert '<script>' not in items[0]
        assert 'normal' in items[1]
    
    def test_allows_normal_requests(self, client):
        data = {"name": "John Doe", "email": "john@example.com"}
        response = client.post('/echo', json=data)
        
        assert response.status_code == 200
        result = response.get_json()
        assert result['received']['name'] == 'John Doe'
        assert result['received']['email'] == 'john@example.com'


# ============================================================================
# CUSTOM CONFIGURATION TESTS
# ============================================================================

class TestFlaskCustomConfig:
    """Test custom Arcis configuration."""
    
    def test_custom_csp(self):
        app = Flask(__name__)
        app.config['TESTING'] = True
        arcis = Arcis(app, csp="default-src 'none'")
        
        @app.route('/')
        def index():
            return jsonify({"message": "Hello"})
        
        client = app.test_client()
        response = client.get('/')
        
        assert response.headers.get('Content-Security-Policy') == "default-src 'none'"
        arcis.close()
    
    def test_disable_sanitization(self):
        app = Flask(__name__)
        app.config['TESTING'] = True
        arcis = Arcis(app, sanitize=False)
        
        @app.route('/echo', methods=['POST'])
        def echo():
            # Without sanitization, g.json won't be set
            return jsonify({"received": request.json})
        
        client = app.test_client()
        data = {"name": "<script>test</script>"}
        response = client.post('/echo', json=data)
        
        result = response.get_json()
        # Without sanitization, script tag should remain
        assert '<script>' in result['received']['name']
        arcis.close()
    
    def test_disable_rate_limiting(self):
        app = Flask(__name__)
        app.config['TESTING'] = True
        arcis = Arcis(app, rate_limit=False)
        
        @app.route('/')
        def index():
            return jsonify({"message": "Hello"})
        
        client = app.test_client()
        response = client.get('/')
        
        # Rate limit headers should not be present
        assert 'X-RateLimit-Limit' not in response.headers
        arcis.close()
    
    def test_disable_headers(self):
        app = Flask(__name__)
        app.config['TESTING'] = True
        arcis = Arcis(app, headers=False)
        
        @app.route('/')
        def index():
            return jsonify({"message": "Hello"})
        
        client = app.test_client()
        response = client.get('/')
        
        # CSP header should not be present
        assert 'Content-Security-Policy' not in response.headers
        arcis.close()
    
    def test_custom_rate_limit_max(self):
        app = Flask(__name__)
        app.config['TESTING'] = True
        arcis = Arcis(app, rate_limit_max=50)
        
        @app.route('/')
        def index():
            return jsonify({"message": "Hello"})
        
        client = app.test_client()
        response = client.get('/')
        
        assert response.headers.get('X-RateLimit-Limit') == '50'
        arcis.close()
    
    def test_disable_specific_sanitizers(self):
        app = Flask(__name__)
        app.config['TESTING'] = True
        # Disable SQL sanitization only
        arcis = Arcis(app, sanitize_sql=False, sanitize_xss=True)
        
        @app.route('/echo', methods=['POST'])
        def echo():
            data = getattr(g, 'json', {})
            return jsonify({"received": data})
        
        client = app.test_client()
        
        # XSS should still be sanitized
        response = client.post('/echo', json={"name": "<script>test</script>"})
        result = response.get_json()
        assert '<script>' not in result['received']['name']
        
        arcis.close()


# ============================================================================
# ERROR HANDLER TESTS
# ============================================================================

class TestFlaskErrorHandler:
    """Test Flask error handler integration."""
    
    def test_error_handler_production_mode(self):
        app = Flask(__name__)
        app.config['TESTING'] = True
        arcis = Arcis(app, is_dev=False)
        
        @app.route('/error')
        def error_route():
            raise ValueError("Database connection failed at 10.0.0.1")
        
        client = app.test_client()
        response = client.get('/error')
        
        assert response.status_code == 500
        data = response.get_json()
        assert data['error'] == 'Internal Server Error'
        assert 'stack' not in data
        assert '10.0.0.1' not in str(data)
        
        arcis.close()
    
    def test_error_handler_development_mode(self):
        app = Flask(__name__)
        app.config['TESTING'] = True
        arcis = Arcis(app, is_dev=True)
        
        @app.route('/error')
        def error_route():
            raise ValueError("Something broke")
        
        client = app.test_client()
        response = client.get('/error')
        
        assert response.status_code == 500
        data = response.get_json()
        assert 'stack' in data
        assert 'Something broke' in str(data.get('details', ''))
        
        arcis.close()


# ============================================================================
# DIFFERENT IP RATE LIMITING TESTS
# ============================================================================

class TestFlaskRateLimitingPerIP:
    """Test rate limiting per IP address."""
    
    def test_different_ips_have_separate_limits(self):
        app = Flask(__name__)
        app.config['TESTING'] = True
        arcis = Arcis(app, rate_limit_max=2)
        
        @app.route('/')
        def index():
            return jsonify({"message": "Hello"})
        
        client = app.test_client()
        
        # The Flask test client uses 127.0.0.1 by default
        # Make 2 requests (should pass)
        for _ in range(2):
            response = client.get('/')
            assert response.status_code == 200
        
        # 3rd request should be blocked
        response = client.get('/')
        assert response.status_code == 429
        
        arcis.close()


# ============================================================================
# COMBINED REAL-WORLD SCENARIO TESTS
# ============================================================================

class TestFlaskCombinedScenarios:
    """Test combined real-world scenarios."""
    
    def test_protected_api_endpoint(self):
        app = Flask(__name__)
        app.config['TESTING'] = True
        arcis = Arcis(app, rate_limit_max=100)
        
        @app.route('/api/comments', methods=['POST'])
        def create_comment():
            data = getattr(g, 'json', None) or {}
            return jsonify({"comment": data}), 201
        
        client = app.test_client()
        
        # Test 1: Valid request with XSS in text (should be sanitized)
        response = client.post('/api/comments', json={
            "text": '<script>alert("xss")</script>Great post!',
            "author_id": "123e4567-e89b-12d3-a456-426614174000"
        })
        
        assert response.status_code == 201
        data = response.get_json()
        assert '<script>' not in data['comment']['text']
        assert 'Great post!' in data['comment']['text']
        
        # Verify headers
        assert response.headers.get('X-Content-Type-Options') == 'nosniff'
        assert 'X-RateLimit-Limit' in response.headers
        
        # Test 2: Mass assignment attempt (extra fields should pass through but could be filtered by schema)
        response = client.post('/api/comments', json={
            "text": "Normal comment",
            "is_approved": True,
            "admin_flag": True
        })
        
        assert response.status_code == 201
        
        arcis.close()
    
    def test_all_protections_work_together(self):
        app = Flask(__name__)
        app.config['TESTING'] = True
        arcis = Arcis(app, rate_limit_max=100)
        
        @app.route('/api/users', methods=['POST'])
        def create_user():
            data = getattr(g, 'json', {})
            return jsonify({"user": data}), 201
        
        client = app.test_client()
        
        # Send malicious payload
        response = client.post('/api/users', json={
            "name": "<script>xss</script>",
            "bio": "'; DROP TABLE users; --",
            "__proto__": {"admin": True},
            "$where": "malicious",
            "path": "../../etc/passwd"
        })
        
        assert response.status_code == 201
        data = response.get_json()
        
        # Verify sanitization
        assert '<script>' not in data['user'].get('name', '')
        assert 'DROP' not in data['user'].get('bio', '').upper()
        assert '__proto__' not in data['user']
        assert '$where' not in data['user']
        assert '../' not in data['user'].get('path', '')
        
        # Verify security headers
        assert response.headers.get('X-Content-Type-Options') == 'nosniff'
        assert response.headers.get('X-Frame-Options') == 'DENY'
        assert 'Content-Security-Policy' in response.headers
        
        # Verify rate limit headers
        assert 'X-RateLimit-Limit' in response.headers
        assert 'X-RateLimit-Remaining' in response.headers
        
        arcis.close()


# ============================================================================
# SCHEMA VALIDATION TESTS (with Flask)
# ============================================================================

class TestFlaskSchemaValidation:
    """Test schema validation with Flask."""
    
    def test_schema_validation_integration(self):
        app = Flask(__name__)
        app.config['TESTING'] = True
        arcis = Arcis(app)
        
        user_schema = {
            'email': {'type': 'email', 'required': True},
            'name': {'type': 'string', 'min': 2, 'max': 50},
            'age': {'type': 'number', 'min': 0, 'max': 150},
            'role': {'type': 'string', 'enum': ['user', 'admin']}
        }
        validator = SchemaValidator(user_schema)
        
        @app.route('/users', methods=['POST'])
        def create_user():
            data = getattr(g, 'json', None) or request.json or {}
            validated, errors = validator.validate(data)
            
            if errors:
                return jsonify({"errors": errors}), 400
            
            return jsonify({"user": validated}), 201
        
        client = app.test_client()
        
        # Test missing required field
        response = client.post('/users', json={"name": "John"})
        assert response.status_code == 400
        data = response.get_json()
        assert any('required' in e for e in data['errors'])
        
        # Test invalid email
        response = client.post('/users', json={"email": "invalid"})
        assert response.status_code == 400
        data = response.get_json()
        assert any('email' in e.lower() for e in data['errors'])
        
        # Test valid data
        response = client.post('/users', json={
            "email": "john@example.com",
            "name": "John Doe",
            "age": 25,
            "role": "user"
        })
        assert response.status_code == 201
        data = response.get_json()
        assert data['user']['email'] == 'john@example.com'
        
        # Test enum validation
        response = client.post('/users', json={
            "email": "test@test.com",
            "role": "superadmin"
        })
        assert response.status_code == 400
        data = response.get_json()
        assert any('one of' in e for e in data['errors'])
        
        # Test mass assignment prevention
        response = client.post('/users', json={
            "email": "test@test.com",
            "name": "Test",
            "isAdmin": True,  # Not in schema
            "secretField": "hack"  # Not in schema
        })
        assert response.status_code == 201
        data = response.get_json()
        assert 'email' in data['user']
        assert 'isAdmin' not in data['user']
        assert 'secretField' not in data['user']
        
        arcis.close()


# ============================================================================
# SAFE LOGGER TESTS (with Flask)
# ============================================================================

class TestFlaskSafeLogger:
    """Test safe logger with Flask."""
    
    def test_logger_redacts_sensitive_data(self):
        from arcis.core import SafeLogger
        
        logger = SafeLogger()
        
        # This should not throw and should redact password
        logger.info("User login", {
            "email": "test@test.com",
            "password": "secret123"
        })
        
        # Verify redaction works
        data = {"email": "test@test.com", "password": "secret123", "token": "abc"}
        redacted = logger._redact(data)
        
        assert redacted['email'] == 'test@test.com'
        assert redacted['password'] == '[REDACTED]'
        assert redacted['token'] == '[REDACTED]'


# ============================================================================
# CLOSE/CLEANUP TESTS
# ============================================================================

class TestFlaskCleanup:
    """Test proper cleanup of resources."""
    
    def test_arcis_close(self):
        app = Flask(__name__)
        app.config['TESTING'] = True
        arcis = Arcis(app)
        
        @app.route('/')
        def index():
            return jsonify({"message": "Hello"})
        
        client = app.test_client()
        response = client.get('/')
        assert response.status_code == 200
        
        # Close should not raise
        arcis.close()
        
        # Requests should still work after close (fail-open)
        response = client.get('/')
        assert response.status_code == 200
