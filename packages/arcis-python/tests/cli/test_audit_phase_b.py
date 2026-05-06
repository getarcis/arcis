"""
Tests for the cli-audit Phase B rule expansion.

Each rule class follows the existing pattern in tests/cli/test_audit.py:
- positive test: a real misuse pattern is caught
- negative test(s): plausible benign code does not false-positive

Rules covered (added 2026-05-05 on feat/v1.5):
- HARDCODED-SECRET
- WEAK-CRYPTO
- WEAK-RANDOM-FOR-SECURITY
- INSECURE-REDIRECT
- XML-EXTERNAL-ENTITY
- SECRET-IN-LOG
- JWT-WEAK-SECRET
- MASS-ASSIGNMENT
- PATH-CONFUSION
"""

from __future__ import annotations

import os
import tempfile

from arcis.cli.audit import scan_file


def _write(content: str, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def _has(rule_id: str, content: str, suffix: str) -> bool:
    path = _write(content, suffix)
    try:
        return any(f.rule_id == rule_id for f in scan_file(path))
    finally:
        os.unlink(path)


# ── HARDCODED-SECRET ────────────────────────────────────────────────────────

# Test fixtures are assembled from split literals so the source file in git
# never contains a string that matches a real-credential format on a single
# line. The temp file written by `_write` does contain the joined form,
# which is exactly what the rule needs to scan.

_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
_GHPAT = "ghp" + "_" + ("a" * 36)
_STRIPE = "sk" + "_live" + "_" + ("z" * 24)
_SLACK = "xoxb" + "-" + "1234567890" + "-" + "abcdefghij"
_RSA_HEADER = "-----BEGIN " + "RSA PRIVATE KEY" + "-----"


class TestHardcodedSecret:
    def test_aws_access_key_id(self) -> None:
        assert _has("HARDCODED-SECRET", f'AWS_KEY = "{_AWS}"\n', ".py")

    def test_github_pat(self) -> None:
        assert _has("HARDCODED-SECRET", f'const t = "{_GHPAT}"\n', ".js")

    def test_stripe_live_key(self) -> None:
        assert _has("HARDCODED-SECRET", f'STRIPE = "{_STRIPE}"\n', ".py")

    def test_slack_bot_token(self) -> None:
        assert _has("HARDCODED-SECRET", f'const slack = "{_SLACK}"\n', ".ts")

    def test_rsa_private_key_marker(self) -> None:
        assert _has("HARDCODED-SECRET", f'const k = "{_RSA_HEADER}"\n', ".js")

    def test_does_not_flag_uuid_or_hash(self) -> None:
        assert not _has(
            "HARDCODED-SECRET",
            'const id = "550e8400-e29b-41d4-a716-446655440000"\n',
            ".js",
        )

    def test_does_not_flag_normal_string(self) -> None:
        assert not _has(
            "HARDCODED-SECRET",
            'const greeting = "hello world"\n',
            ".js",
        )


# ── WEAK-CRYPTO ─────────────────────────────────────────────────────────────

class TestWeakCrypto:
    def test_python_hashlib_md5(self) -> None:
        assert _has("WEAK-CRYPTO", "h = hashlib.md5(password)\n", ".py")

    def test_python_hashlib_sha1(self) -> None:
        assert _has("WEAK-CRYPTO", "h = hashlib.sha1(data)\n", ".py")

    def test_node_create_hash_md5(self) -> None:
        assert _has(
            "WEAK-CRYPTO",
            "const h = crypto.createHash('md5').update(p).digest('hex')\n",
            ".js",
        )

    def test_node_create_cipher_des(self) -> None:
        assert _has("WEAK-CRYPTO", "const c = crypto.createCipher('des', key)\n", ".ts")

    def test_does_not_flag_sha256(self) -> None:
        assert not _has("WEAK-CRYPTO", "h = hashlib.sha256(data)\n", ".py")

    def test_does_not_flag_blake2(self) -> None:
        assert not _has("WEAK-CRYPTO", "h = hashlib.blake2b(data)\n", ".py")


# ── WEAK-RANDOM-FOR-SECURITY ────────────────────────────────────────────────

class TestWeakRandomForSecurity:
    def test_js_token_from_math_random(self) -> None:
        assert _has(
            "WEAK-RANDOM-FOR-SECURITY",
            "const token = Math.random().toString(36)\n",
            ".js",
        )

    def test_python_csrf_from_random_random(self) -> None:
        assert _has(
            "WEAK-RANDOM-FOR-SECURITY",
            "csrf_token = random.random()\n",
            ".py",
        )

    def test_python_session_from_randint(self) -> None:
        assert _has(
            "WEAK-RANDOM-FOR-SECURITY",
            "session_id = random.randint(0, 2**31)\n",
            ".py",
        )

    def test_does_not_flag_animation_delay(self) -> None:
        assert not _has(
            "WEAK-RANDOM-FOR-SECURITY",
            "const delay = Math.random() * 1000\n",
            ".js",
        )

    def test_does_not_flag_secrets_token_hex(self) -> None:
        assert not _has(
            "WEAK-RANDOM-FOR-SECURITY",
            "token = secrets.token_hex(32)\n",
            ".py",
        )


# ── INSECURE-REDIRECT ───────────────────────────────────────────────────────

class TestInsecureRedirect:
    def test_express_redirect_from_query(self) -> None:
        assert _has(
            "INSECURE-REDIRECT",
            "app.get('/r', (req, res) => res.redirect(req.query.next))\n",
            ".js",
        )

    def test_django_redirect_from_request_get(self) -> None:
        assert _has(
            "INSECURE-REDIRECT",
            "return redirect(request.GET.get('next'))\n",
            ".py",
        )

    def test_does_not_flag_static_redirect(self) -> None:
        assert not _has(
            "INSECURE-REDIRECT",
            "res.redirect('/login')\n",
            ".js",
        )

    def test_does_not_flag_validated_redirect(self) -> None:
        assert not _has(
            "INSECURE-REDIRECT",
            "res.redirect(allowedHosts[0])\n",
            ".js",
        )


# ── XML-EXTERNAL-ENTITY ─────────────────────────────────────────────────────

class TestXmlExternalEntity:
    def test_lxml_etree_parse(self) -> None:
        assert _has(
            "XML-EXTERNAL-ENTITY",
            "tree = lxml.etree.parse(stream)\n",
            ".py",
        )

    def test_minidom_parse(self) -> None:
        assert _has(
            "XML-EXTERNAL-ENTITY",
            "doc = xml.dom.minidom.parse(file)\n",
            ".py",
        )

    def test_node_xml2js_parser(self) -> None:
        assert _has(
            "XML-EXTERNAL-ENTITY",
            "const parser = new xml2js.Parser()\n",
            ".js",
        )

    def test_does_not_flag_json_parse(self) -> None:
        assert not _has(
            "XML-EXTERNAL-ENTITY",
            "const data = JSON.parse(input)\n",
            ".js",
        )


# ── SECRET-IN-LOG ───────────────────────────────────────────────────────────

class TestSecretInLog:
    def test_console_log_password(self) -> None:
        assert _has(
            "SECRET-IN-LOG",
            'console.log("user logged in", password)\n',
            ".js",
        )

    def test_python_print_token(self) -> None:
        assert _has(
            "SECRET-IN-LOG",
            'print(f"got token: {access_token}")\n',
            ".py",
        )

    def test_logger_info_secret(self) -> None:
        assert _has(
            "SECRET-IN-LOG",
            'logger.info("client_secret rotated:", new_secret)\n',
            ".py",
        )

    def test_does_not_flag_user_id_log(self) -> None:
        assert not _has(
            "SECRET-IN-LOG",
            'console.log("user logged in", userId)\n',
            ".js",
        )


# ── JWT-WEAK-SECRET ─────────────────────────────────────────────────────────

class TestJwtWeakSecret:
    def test_jwt_sign_with_string_literal(self) -> None:
        assert _has(
            "JWT-WEAK-SECRET",
            "const tok = jwt.sign(payload, 'mysecret')\n",
            ".js",
        )

    def test_jwt_sign_with_env_fallback_to_literal(self) -> None:
        assert _has(
            "JWT-WEAK-SECRET",
            "const tok = jwt.sign(payload, process.env.JWT_SECRET || 'dev')\n",
            ".ts",
        )

    def test_does_not_flag_jwt_sign_with_env_only(self) -> None:
        assert not _has(
            "JWT-WEAK-SECRET",
            "const tok = jwt.sign(payload, process.env.JWT_SECRET)\n",
            ".js",
        )

    def test_does_not_flag_jwt_sign_with_module_secret(self) -> None:
        assert not _has(
            "JWT-WEAK-SECRET",
            "const tok = jwt.sign(payload, secretConfig.value)\n",
            ".js",
        )


# ── MASS-ASSIGNMENT ─────────────────────────────────────────────────────────

class TestMassAssignment:
    def test_object_assign_user_req_body(self) -> None:
        assert _has(
            "MASS-ASSIGNMENT",
            "Object.assign(user, req.body)\n",
            ".js",
        )

    def test_object_assign_with_query(self) -> None:
        assert _has(
            "MASS-ASSIGNMENT",
            "Object.assign(target, req.query)\n",
            ".ts",
        )

    def test_python_setattr_double_splat_request(self) -> None:
        assert _has(
            "MASS-ASSIGNMENT",
            "setattr(user, **request.POST)\n",
            ".py",
        )

    def test_does_not_flag_object_assign_with_static_object(self) -> None:
        assert not _has(
            "MASS-ASSIGNMENT",
            "Object.assign(target, defaults)\n",
            ".js",
        )


# ── PATH-CONFUSION ──────────────────────────────────────────────────────────

class TestPathConfusion:
    def test_node_path_join_req_params(self) -> None:
        assert _has(
            "PATH-CONFUSION",
            "const p = path.join(BASE, req.params.file)\n",
            ".js",
        )

    def test_node_path_join_query(self) -> None:
        assert _has(
            "PATH-CONFUSION",
            "const p = path.join(uploadDir, req.query.name)\n",
            ".ts",
        )

    def test_python_path_join_request_args(self) -> None:
        assert _has(
            "PATH-CONFUSION",
            "p = os.path.join(BASE, request.args.get('file'))\n",
            ".py",
        )

    def test_does_not_flag_path_join_with_static(self) -> None:
        assert not _has(
            "PATH-CONFUSION",
            "const p = path.join(__dirname, 'public', 'index.html')\n",
            ".js",
        )
