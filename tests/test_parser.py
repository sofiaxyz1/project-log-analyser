import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

from analyzer import parse_line


def test_parse_line_valida_retorna_logentry():
    line = '192.168.0.10 - - [14/Feb/2026:10:01:01 -0300] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
    entry = parse_line(line)

    assert entry is not None
    assert entry.ip == "192.168.0.10"
    assert entry.method == "GET"
    assert entry.path == "/"
    assert entry.status == 200
    assert entry.user_agent == "Mozilla/5.0"


def test_parse_line_invalida_retorna_none():
    line = "isso nao eh um log valido"
    entry = parse_line(line)

    assert entry is None


def test_parse_line_status_401():
    line = '192.168.0.10 - - [14/Feb/2026:10:01:03 -0300] "POST /login HTTP/1.1" 401 210 "-" "Mozilla/5.0"'
    entry = parse_line(line)

    assert entry is not None
    assert entry.status == 401
    assert entry.path == "/login"

