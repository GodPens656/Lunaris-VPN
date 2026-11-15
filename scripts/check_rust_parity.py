"""Run legacy regression fixtures against both implementations.

Python remains a test oracle only. Every parser/configuration call is compared
with the compiled Rust backend before the original assertions are evaluated.
"""
from dataclasses import asdict
from pathlib import Path
import argparse
import functools
import inspect
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]


class Parity:
    def __init__(self, executable):
        self.child = subprocess.Popen([str(executable)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, text=True, encoding="utf-8")
        self.compared = 0

    def request(self, data):
        self.child.stdin.write(json.dumps(data, ensure_ascii=False) + "\n")
        self.child.stdin.flush()
        line = self.child.stdout.readline()
        assert line, "Rust diagnostic process stopped"
        return json.loads(line)

    def wrap(self, module, name, request, serialize=lambda v: v):
        original = getattr(module, name)
        signature = inspect.signature(original)

        @functools.wraps(original)
        def check(*args, **kwargs):
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            from sever.models import UserError
            try:
                expected = original(*args, **kwargs)
            except UserError:
                response = self.request(request(bound.arguments))
                assert "error" in response, f"Rust accepted rejected {name} input"
                self.compared += 1
                raise
            response = self.request(request(bound.arguments))
            assert "ok" in response, f"Rust rejected valid {name}: {response.get('error')}"
            assert response["ok"] == serialize(expected), f"Rust/Python {name} output differs"
            self.compared += 1
            return expected
        setattr(module, name, check)

    def pytest_configure(self, config):
        from sever import parser, config as sing, xray, mihomo
        from sever.models import Settings

        def common(v, core):
            data = {"method": "config", "core": core, "profile": asdict(v["profile"]),
                "settings": asdict(v.get("settings") or Settings())}
            if v.get("endpoint_hosts") is not None:
                data["hosts"] = v["endpoint_hosts"]
            return data

        self.wrap(parser, "parse_uri", lambda v: {"method": "parse", "uri": v["uri"], "source": v["source_id"]},
            lambda p: {"profile": asdict(p), "identity": p.identity, "key": p.key, "requires_xray": p.requires_xray})
        self.wrap(sing, "build_config", lambda v: {**common(v, "sing-box"), "secret": v["api_secret"],
            "android": v["android"], "sidecar": v["sidecar"]})
        self.wrap(xray, "build_xray_config", lambda v: {**common(v, "xray"), "port": v["port"], "password": v["password"]})
        self.wrap(mihomo, "build_mihomo_config", lambda v: {**common(v, "mihomo"), "secret": v["api_secret"]})
        self.wrap(mihomo, "build_proxy", lambda v: common(v, "mihomo-proxy"))

    def pytest_sessionfinish(self, session, exitstatus):
        print(f"\nRust/Python parity: {self.compared} matching parser/configuration calls")

    def close(self):
        self.child.stdin.close()
        self.child.wait(timeout=10)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("executable", type=Path)
    ap.add_argument("--full", action="store_true", help="Run every legacy test, including native loopback integration")
    known, args = ap.parse_known_args()
    import pytest
    plugin = Parity(known.executable.resolve())
    try:
        selection=[] if known.full else ["tests/test_parser.py", "tests/test_config.py",
            "tests/test_share_compatibility.py", "tests/test_grpc.py", "tests/test_mihomo.py",
            "tests/test_routing.py", "-m", "not core", "-q"]
        raise SystemExit(pytest.main(selection+args, plugins=[plugin]))
    finally:
        plugin.close()
