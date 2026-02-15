import argparse
import re
from dataclasses import dataclass
from typing import Optional, Iterable
from collections import Counter

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

def read_entries(filepath: str) -> Iterable[LogEntry]:
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            entry = parse_line(line)
            if entry:
                yield entry

def main():
    ap = argparse.ArgumentParser(description="Log Analyzer")
    ap.add_argument("--input", required=True, help="Path to access log file")
    ap.add_argument("--top", type=int, default=10, help="Top N results to show")
    args = ap.parse_args()

    ip_counter = Counter()
    status_counter = Counter()
    endpoint_counter = Counter()

    parsed = 0
    for e in read_entries(args.input):
        parsed += 1
        ip_counter[e.ip] += 1
        status_counter[e.status] += 1
        endpoint_counter[e.path] += 1

    print("\n=== Log Analyzer Summary ===")
    print(f"Parsed entries: {parsed}")

    print("\nTop IPs:")
    for ip, c in ip_counter.most_common(args.top):
        print(f"  {ip}: {c}")

    print("\nStatus codes:")
    for st, c in status_counter.most_common():
        print(f"  {st}: {c}")

    print("\nTop endpoints:")
    for ep, c in endpoint_counter.most_common(args.top):
        print(f"  {ep}: {c}")

if __name__ == "__main__":
    main()
