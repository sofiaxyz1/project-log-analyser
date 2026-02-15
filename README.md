# 🔍 Log Analyzer em Python

Ferramenta desenvolvida para analisar arquivos de log de acesso (access logs), extrair informações relevantes e gerar relatórios estatísticos com possíveis indícios de comportamento suspeito.

---

## 📌 Objetivo

Este projeto tem como objetivo:

- Realizar parsing estruturado de logs de servidor
- Gerar métricas sobre requisições HTTP
- Identificar padrões potencialmente suspeitos (ex: múltiplos erros 401/403)
- Exportar relatório em formato CSV

---

## 🛠 Tecnologias utilizadas

- Python 3
- Regex (Expressões Regulares)
- argparse
- collections (Counter, defaultdict)
- csv
- datetime

---

## ⚙️ Funcionalidades

✔ Leitura de arquivo de log  
✔ Extração estruturada de IP, data, método, endpoint e status  
✔ Contagem de requisições por IP  
✔ Distribuição de códigos HTTP  
✔ Ranking de endpoints mais acessados  
✔ Heurística simples para detecção de possíveis tentativas de força bruta  
✔ Exportação de relatório em CSV  

---

## 🧠 Como funciona

1. Cada linha do log é processada por uma expressão regular (regex).
2. As informações extraídas são convertidas em objetos estruturados.
3. São geradas estatísticas utilizando contadores.
4. É aplicada uma heurística básica para identificar IPs com múltiplos erros de autenticação.
5. Um relatório consolidado é exportado para CSV.

---

## ▶️ Como executar

```bash
python analyzer.py --input sample_logs/access.log --out relatorio.csv
