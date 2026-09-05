"""Security regression tests for ir_validate.py."""

import os
import tempfile

import ir_validate


SIMPLE_PROGRAM = '''munus main() {
    imprimo("hello")
}
'''


def _write_lat_file(directory, filename, content):
    path = os.path.join(directory, filename)
    with open(path, "w") as f:
        f.write(content)
    return path


def test_malicious_filename_does_not_inject_code():
    """A filename crafted to break out of a Python string literal must not
    execute arbitrary code.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Filename chosen to terminate a Python -c string literal and inject
        # an os.system() call.  With the old subprocess implementation this
        # would execute `id` in the validator's interpreter.
        malicious = "test';__import__('os').system('id');#.lat"
        filepath = _write_lat_file(tmpdir, malicious, SIMPLE_PROGRAM)

        ok, out_path, stderr = ir_validate.compile_file(filepath)

        # The file is not a real source file the compiler can read as a normal
        # .lat path, so compilation should fail, but it must fail safely (no
        # injected code executes).  We verify safety by checking stderr does
        # not contain command output and the function returns instead of
        # raising or launching a process.
        assert not ok or os.path.exists(out_path)
        assert "uid=" not in stderr
        assert "gid=" not in stderr


def test_compile_ast_with_malicious_filename_is_safe():
    with tempfile.TemporaryDirectory() as tmpdir:
        malicious = "x\";__import__('os').system('id');#.lat"
        filepath = _write_lat_file(tmpdir, malicious, SIMPLE_PROGRAM)

        ok, out_path, stderr = ir_validate.compile_ast(filepath)

        assert not ok or os.path.exists(out_path)
        assert "uid=" not in stderr
        assert "gid=" not in stderr


def test_compile_file_valid_program():
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = _write_lat_file(tmpdir, "hello.lat", SIMPLE_PROGRAM)

        ok, out_path, stderr = ir_validate.compile_file(filepath)

        assert ok, stderr
        assert os.path.exists(out_path)
        with open(out_path) as f:
            content = f.read()
        assert "start" in content
        os.unlink(out_path)


def test_compile_ast_valid_program():
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = _write_lat_file(tmpdir, "hello.lat", SIMPLE_PROGRAM)

        ok, out_path, stderr = ir_validate.compile_ast(filepath)

        assert ok, stderr
        assert os.path.exists(out_path)
        with open(out_path) as f:
            content = f.read()
        assert "start" in content
        os.unlink(out_path)
