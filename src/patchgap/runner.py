"""Command runners. Everything that touches the system goes through a Runner so tests can
swap in a fake and dry-runs can print instead of execute."""
import subprocess


class Result:
    def __init__(self, rc=0, out="", err=""):
        self.rc, self.out, self.err = rc, out, err

    @property
    def ok(self):
        return self.rc == 0


class Runner:
    """Runs real commands."""

    def run(self, cmd, input=None, timeout=120):
        try:
            p = subprocess.run(cmd, input=input, capture_output=True, text=True, timeout=timeout)
            return Result(p.returncode, p.stdout, p.stderr)
        except FileNotFoundError as e:
            return Result(127, "", str(e))
        except subprocess.TimeoutExpired:
            return Result(124, "", f"timeout after {timeout}s: {' '.join(cmd)}")


class FakeRunner(Runner):
    """Test runner: answers from a table of {command-prefix-tuple: Result or callable}."""

    def __init__(self, answers=None, default=None):
        self.answers = dict(answers or {})
        self.default = default or Result(0, "", "")
        self.calls = []

    def run(self, cmd, input=None, timeout=120):
        self.calls.append(list(cmd))
        best = None
        for key, val in self.answers.items():
            if tuple(cmd[:len(key)]) == tuple(key) and (best is None or len(key) > len(best[0])):
                best = (key, val)
        if best is None:
            return self.default
        val = best[1]
        return val(cmd, input) if callable(val) else val
