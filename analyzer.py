import argparse
import re
import csv
from datetime import datetime
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
    from collections import defaultdict
    
    ap = argparse.ArgumentParser(description="Log Analyzer")
    ap.add_argument("--input", required=True, help="Path to access log file")
    ap.add_argument("--top", type=int, default=10, help="Top N results to show")
    ap.add_argument("--out", default="relatorio.csv", help="Caminho do CSV de saída")
    args = ap.parse_args()

    ip_counter = Counter()
    status_counter = Counter()
    endpoint_counter = Counter()
    
    parsed = 0
    ip_status = defaultdict(Counter)
    for e in read_entries(args.input):
        parsed += 1
        ip_counter[e.ip] += 1
        status_counter[e.status] += 1
        endpoint_counter[e.path] += 1
        ip_status[e.ip][e.status] += 1


    print("\n=== Resumo da Análise de Logs ===")
    print(f"Entradas analisadas: {parsed}")

    print("\nIPs com mais requisições:")
    for ip, c in ip_counter.most_common(args.top):
        print(f"  {ip}: {c}")

    print("\nDistribuição de códigos HTTP:")
    for st, c in status_counter.most_common():
        print(f"  {st}: {c}")

    print("\nEndpoints mais acessados:")
    for ep, c in endpoint_counter.most_common(args.top):
        print(f"  {ep}: {c}")

    print("\nIPs suspeitos (heurística básica):")
    for ip, statuses in ip_status.items():
        total_erros = statuses[401] + statuses[403]
        if total_erros >= 2:
            print(f"  {ip} pode estar tentando força bruta (401/403: {total_erros})")

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)

        w.writerow(["gerado_em", datetime.utcnow().isoformat() + "Z"])
        w.writerow([])

        w.writerow(["metrica", "chave", "valor"])

        for ip, c in ip_counter.most_common():
            w.writerow(["requisicoes_por_ip", ip, c])

        for st, c in status_counter.most_common():
            w.writerow(["codigo_http", st, c])

        for ep, c in endpoint_counter.most_common():
            w.writerow(["endpoint", ep, c])

        w.writerow([])
        w.writerow(["ips_suspeitos", "ip", "qtd_401_403"])
        for ip, statuses in ip_status.items():
            total_erros = statuses[401] + statuses[403]
        if total_erros >= 2:
            w.writerow(["suspeito", ip, total_erros])

    print(f"\n✅ CSV gerado em: {args.out}")

if __name__ == "__main__":
    main()
