"""
Tests for arcis audit — static analysis security scanner.
Tests for arcis/cli/audit.py
"""

import os
import tempfile

import pytest
from arcis.cli.audit import scan_file, scan_directory, Finding, RULES


# ── Helper ───────────────────────────────────────────────────────────────────

def _write_temp(content: str, suffix: str) -> str:
    """Write content to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


# ── Python rules ─────────────────────────────────────────────────────────────

class TestYamlUnsafe:
    """Test YAML-UNSAFE rule."""

    def test_detects_yaml_load(self):
        path = _write_temp("import yaml\ndata = yaml.load(f)\n", ".py")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "YAML-UNSAFE" for f in findings)
        finally:
            os.unlink(path)

    def test_allows_yaml_safe_load(self):
        path = _write_temp("import yaml\ndata = yaml.safe_load(f)\n", ".py")
        try:
            findings = scan_file(path)
            assert not any(f.rule_id == "YAML-UNSAFE" for f in findings)
        finally:
            os.unlink(path)

    def test_allows_yaml_load_with_safeloader(self):
        path = _write_temp("data = yaml.load(f, Loader=SafeLoader)\n", ".py")
        try:
            findings = scan_file(path)
            assert not any(f.rule_id == "YAML-UNSAFE" for f in findings)
        finally:
            os.unlink(path)

    def test_allows_yaml_load_with_yaml_safeloader(self):
        path = _write_temp("data = yaml.load(f, Loader=yaml.SafeLoader)\n", ".py")
        try:
            findings = scan_file(path)
            assert not any(f.rule_id == "YAML-UNSAFE" for f in findings)
        finally:
            os.unlink(path)


class TestShellTrue:
    """Test SHELL-TRUE rule."""

    def test_detects_subprocess_call_shell_true(self):
        path = _write_temp("import subprocess\nsubprocess.call(cmd, shell=True)\n", ".py")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "SHELL-TRUE" for f in findings)
        finally:
            os.unlink(path)

    def test_detects_subprocess_run_shell_true(self):
        path = _write_temp("subprocess.run(cmd, shell=True)\n", ".py")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "SHELL-TRUE" for f in findings)
        finally:
            os.unlink(path)

    def test_detects_subprocess_popen_shell_true(self):
        path = _write_temp("subprocess.Popen(cmd, shell=True)\n", ".py")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "SHELL-TRUE" for f in findings)
        finally:
            os.unlink(path)

    def test_allows_shell_false(self):
        path = _write_temp("subprocess.run(['ls', '-la'], shell=False)\n", ".py")
        try:
            findings = scan_file(path)
            assert not any(f.rule_id == "SHELL-TRUE" for f in findings)
        finally:
            os.unlink(path)

    def test_allows_no_shell_param(self):
        path = _write_temp("subprocess.run(['ls', '-la'])\n", ".py")
        try:
            findings = scan_file(path)
            assert not any(f.rule_id == "SHELL-TRUE" for f in findings)
        finally:
            os.unlink(path)


class TestPickleLoad:
    """Test PICKLE-LOAD rule."""

    def test_detects_pickle_loads(self):
        path = _write_temp("import pickle\ndata = pickle.loads(raw)\n", ".py")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "PICKLE-LOAD" for f in findings)
        finally:
            os.unlink(path)

    def test_detects_pickle_load(self):
        path = _write_temp("data = pickle.load(f)\n", ".py")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "PICKLE-LOAD" for f in findings)
        finally:
            os.unlink(path)


class TestEvalExecPython:
    """Test EVAL-EXEC rule in Python."""

    def test_detects_eval(self):
        path = _write_temp("result = eval(user_input)\n", ".py")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "EVAL-EXEC" for f in findings)
        finally:
            os.unlink(path)

    def test_detects_exec(self):
        path = _write_temp("exec(code_string)\n", ".py")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "EVAL-EXEC" for f in findings)
        finally:
            os.unlink(path)


# ── JavaScript/TypeScript rules ──────────────────────────────────────────────

class TestInnerHTML:
    """Test INNERHTML rule."""

    def test_detects_innerhtml(self):
        path = _write_temp("element.innerHTML = userInput;\n", ".js")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "INNERHTML" for f in findings)
        finally:
            os.unlink(path)

    def test_allows_textcontent(self):
        path = _write_temp("element.textContent = userInput;\n", ".js")
        try:
            findings = scan_file(path)
            assert not any(f.rule_id == "INNERHTML" for f in findings)
        finally:
            os.unlink(path)


class TestDocumentWrite:
    """Test DOCUMENT-WRITE rule."""

    def test_detects_document_write(self):
        path = _write_temp("document.write(data);\n", ".js")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "DOCUMENT-WRITE" for f in findings)
        finally:
            os.unlink(path)

    def test_detects_document_writeln(self):
        path = _write_temp("document.writeln(data);\n", ".js")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "DOCUMENT-WRITE" for f in findings)
        finally:
            os.unlink(path)


class TestAngularTrustBypass:
    """Test ANGULAR-TRUST rule."""

    def test_detects_bypass_security_trust_html(self):
        path = _write_temp("this.sanitizer.bypassSecurityTrustHtml(input);\n", ".ts")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "ANGULAR-TRUST" for f in findings)
        finally:
            os.unlink(path)

    def test_detects_bypass_security_trust_url(self):
        path = _write_temp("this.sanitizer.bypassSecurityTrustUrl(input);\n", ".ts")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "ANGULAR-TRUST" for f in findings)
        finally:
            os.unlink(path)

    def test_not_triggered_for_js_files(self):
        path = _write_temp("this.sanitizer.bypassSecurityTrustHtml(input);\n", ".js")
        try:
            findings = scan_file(path)
            assert not any(f.rule_id == "ANGULAR-TRUST" for f in findings)
        finally:
            os.unlink(path)


class TestJwtNoAlgorithm:
    """Test JWT-NO-ALG rule."""

    def test_detects_jwt_verify_no_alg(self):
        path = _write_temp("const decoded = jwt.verify(token, secret);\n", ".js")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "JWT-NO-ALG" for f in findings)
        finally:
            os.unlink(path)

    def test_allows_jwt_verify_with_algorithms(self):
        path = _write_temp("jwt.verify(token, secret, { algorithms: ['RS256'] });\n", ".js")
        try:
            findings = scan_file(path)
            assert not any(f.rule_id == "JWT-NO-ALG" for f in findings)
        finally:
            os.unlink(path)

    def test_detects_jwt_decode_no_alg(self):
        path = _write_temp("const data = jwt.decode(token);\n", ".ts")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "JWT-NO-ALG" for f in findings)
        finally:
            os.unlink(path)


class TestEvalExecJS:
    """Test EVAL-EXEC rule in JavaScript."""

    def test_detects_eval_js(self):
        path = _write_temp("const result = eval(code);\n", ".js")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "EVAL-EXEC" for f in findings)
        finally:
            os.unlink(path)


class TestJsonpCallback:
    """Test JSONP-CALLBACK rule."""

    def test_detects_python_flask_callback(self):
        path = _write_temp("cb = request.args.get('callback')\n", ".py")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "JSONP-CALLBACK" for f in findings)
        finally:
            os.unlink(path)

    def test_detects_express_callback(self):
        path = _write_temp("const cb = req.query.callback;\n", ".js")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "JSONP-CALLBACK" for f in findings)
        finally:
            os.unlink(path)


# ── Comment skipping ─────────────────────────────────────────────────────────

class TestCommentSkipping:
    """Test that comments are not flagged."""

    def test_skips_python_comment(self):
        path = _write_temp("# eval(dangerous)\n", ".py")
        try:
            findings = scan_file(path)
            assert len(findings) == 0
        finally:
            os.unlink(path)

    def test_skips_js_comment(self):
        path = _write_temp("// eval(dangerous)\n", ".js")
        try:
            findings = scan_file(path)
            assert len(findings) == 0
        finally:
            os.unlink(path)


# ── Directory scanning ───────────────────────────────────────────────────────

class TestScanDirectory:
    """Test scan_directory()."""

    def test_scans_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a Python file with an issue
            py_file = os.path.join(tmpdir, "app.py")
            with open(py_file, "w") as f:
                f.write("import pickle\ndata = pickle.loads(raw)\n")

            # Create a safe JS file
            js_file = os.path.join(tmpdir, "app.js")
            with open(js_file, "w") as f:
                f.write("const x = 1;\n")

            findings = scan_directory(tmpdir)
            assert len(findings) >= 1
            assert any(f.rule_id == "PICKLE-LOAD" for f in findings)

    def test_language_filter(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            py_file = os.path.join(tmpdir, "app.py")
            with open(py_file, "w") as f:
                f.write("eval(x)\n")

            js_file = os.path.join(tmpdir, "app.js")
            with open(js_file, "w") as f:
                f.write("eval(x);\n")

            py_only = scan_directory(tmpdir, language="python")
            js_only = scan_directory(tmpdir, language="javascript")

            py_files = {f.file for f in py_only}
            js_files = {f.file for f in js_only}

            assert all(f.endswith(".py") for f in py_files)
            assert all(f.endswith(".js") for f in js_files)

    def test_severity_filter(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            py_file = os.path.join(tmpdir, "app.py")
            with open(py_file, "w") as f:
                f.write("pickle.loads(x)\neval(y)\n")

            all_findings = scan_directory(tmpdir)
            critical_only = scan_directory(tmpdir, severity="critical")

            assert len(critical_only) <= len(all_findings)
            assert all(f.severity == "critical" for f in critical_only)

    def test_skips_node_modules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nm_dir = os.path.join(tmpdir, "node_modules", "pkg")
            os.makedirs(nm_dir)
            bad_file = os.path.join(nm_dir, "index.js")
            with open(bad_file, "w") as f:
                f.write("eval(x);\n")

            findings = scan_directory(tmpdir)
            assert len(findings) == 0


# ── Finding dataclass ────────────────────────────────────────────────────────

# ── New rules (v1.4.0) ───────────────────────────────────────────────────────

class TestSqlConcat:
    """Test SQL-CONCAT rule."""

    def test_detects_fstring_execute(self):
        path = _write_temp('cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n', ".py")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "SQL-CONCAT" for f in findings)
        finally:
            os.unlink(path)

    def test_detects_string_concat_execute(self):
        path = _write_temp('db.execute("SELECT * FROM users WHERE id = " + user_id)\n', ".py")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "SQL-CONCAT" for f in findings)
        finally:
            os.unlink(path)

    def test_allows_parameterized_query(self):
        path = _write_temp('cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n', ".py")
        try:
            findings = scan_file(path)
            assert not any(f.rule_id == "SQL-CONCAT" for f in findings)
        finally:
            os.unlink(path)

    def test_only_python_language(self):
        path = _write_temp('cursor.execute(f"SELECT * FROM users WHERE id = {id}")\n', ".js")
        try:
            findings = scan_file(path)
            assert not any(f.rule_id == "SQL-CONCAT" for f in findings)
        finally:
            os.unlink(path)


class TestOrmRaw:
    """Test ORM-RAW rule."""

    def test_detects_prisma_queryraw(self):
        path = _write_temp("const users = await prisma.$queryRaw`SELECT * FROM users`;\n", ".ts")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "ORM-RAW" for f in findings)
        finally:
            os.unlink(path)

    def test_detects_knex_raw(self):
        path = _write_temp('const result = await knex.raw("SELECT * FROM users WHERE id = ?", [id]);\n', ".ts")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "ORM-RAW" for f in findings)
        finally:
            os.unlink(path)

    def test_detects_sequelize_query(self):
        path = _write_temp('const result = await sequelize.query("SELECT * FROM users");\n', ".js")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "ORM-RAW" for f in findings)
        finally:
            os.unlink(path)

    def test_only_js_ts(self):
        path = _write_temp('sequelize.query("SELECT * FROM users")\n', ".py")
        try:
            findings = scan_file(path)
            assert not any(f.rule_id == "ORM-RAW" for f in findings)
        finally:
            os.unlink(path)


class TestFsUserPath:
    """Test FS-USER-PATH rule."""

    def test_detects_fs_readfile_with_req(self):
        path = _write_temp("fs.readFile(req.query.filename, 'utf8', callback);\n", ".js")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "FS-USER-PATH" for f in findings)
        finally:
            os.unlink(path)

    def test_detects_fs_writefile_with_req_body(self):
        path = _write_temp("fs.writeFile(req.body.path, data, callback);\n", ".ts")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "FS-USER-PATH" for f in findings)
        finally:
            os.unlink(path)

    def test_allows_safe_path(self):
        path = _write_temp("fs.readFile('/etc/config.json', 'utf8', callback);\n", ".js")
        try:
            findings = scan_file(path)
            assert not any(f.rule_id == "FS-USER-PATH" for f in findings)
        finally:
            os.unlink(path)


class TestFetchUserUrl:
    """Test FETCH-USER-URL rule."""

    def test_detects_fetch_with_req_query(self):
        path = _write_temp("const res = await fetch(req.query.url);\n", ".js")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "FETCH-USER-URL" for f in findings)
        finally:
            os.unlink(path)

    def test_detects_fetch_with_template_literal(self):
        path = _write_temp("const res = await fetch(`https://api.example.com/${req.params.id}`);\n", ".ts")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "FETCH-USER-URL" for f in findings)
        finally:
            os.unlink(path)

    def test_detects_requests_get_with_request(self):
        path = _write_temp("resp = requests.get(request.args.get('url'))\n", ".py")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "FETCH-USER-URL" for f in findings)
        finally:
            os.unlink(path)

    def test_allows_hardcoded_url(self):
        path = _write_temp('const res = await fetch("https://api.example.com/data");\n', ".js")
        try:
            findings = scan_file(path)
            assert not any(f.rule_id == "FETCH-USER-URL" for f in findings)
        finally:
            os.unlink(path)


class TestUnsafeDeserialize:
    """Test UNSAFE-DESERIALIZE rule."""

    def test_detects_marshal_loads(self):
        path = _write_temp("import marshal\ndata = marshal.loads(raw)\n", ".py")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "UNSAFE-DESERIALIZE" for f in findings)
        finally:
            os.unlink(path)

    def test_detects_shelve_open(self):
        path = _write_temp("db = shelve.open(filename)\n", ".py")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "UNSAFE-DESERIALIZE" for f in findings)
        finally:
            os.unlink(path)

    def test_detects_jsonpickle_decode(self):
        path = _write_temp("obj = jsonpickle.decode(user_data)\n", ".py")
        try:
            findings = scan_file(path)
            assert any(f.rule_id == "UNSAFE-DESERIALIZE" for f in findings)
        finally:
            os.unlink(path)

    def test_only_python_language(self):
        path = _write_temp("const obj = jsonpickle.decode(userData);\n", ".js")
        try:
            findings = scan_file(path)
            assert not any(f.rule_id == "UNSAFE-DESERIALIZE" for f in findings)
        finally:
            os.unlink(path)


class TestRuleCount:
    """Verify expected number of rules is present."""

    def test_total_rules_count(self):
        assert len(RULES) == 14


# ── Finding dataclass ────────────────────────────────────────────────────────

class TestFinding:
    """Test Finding data structure."""

    def test_finding_fields(self):
        f = Finding(
            rule_id="TEST",
            severity="high",
            message="test message",
            file="test.py",
            line=1,
            snippet="test code",
        )
        assert f.rule_id == "TEST"
        assert f.severity == "high"
        assert f.line == 1
