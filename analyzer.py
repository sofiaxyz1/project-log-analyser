import re
from dataclasses import dataclass
from typing import Optional

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/(?P<httpver>[\d.]+))?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+'
    r'"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

@dataclass
class LogEntry:
    ip: str
    timestamp: str
    method: str
    path: str
    status: int
    referrer: str
    user_agent: str

def parse_line(line: str) -> Optional[LogEntry]:
    m = LOG_PATTERN.match(line.strip())
    if not m:
        return None
    return LogEntry(
        ip=m.group("ip"),
        timestamp=m.group("time"),
        method=m.group("method"),
        path=m.group("path"),
        status=int(m.group("status")),
        referrer=m.group("ref"),
        user_agent=m.group("ua"),
    )

if __name__ == "__main__":
    test_line = '192.168.0.10 - - [14/Feb/2026:10:01:01 -0300] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
    print("Line:", test_line)
    print("Regex match:", bool(LOG_PATTERN.match(test_line)))
    print("Parsed:", parse_line(test_line))
