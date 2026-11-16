"""8c: LLM multi-step 검증."""
import sys
sys.path.insert(0, '.')
from core.models import Asset
from scanner.llm import _execute_steps
from scanner.login import get_authenticated_client
B = "http://localhost:8081"
P = "/vulnerabilities/sqli/"
c = get_authenticated_client(Asset(base_url=B))
s = [
    {"action": "login", "url": B + "/login.php",
     "body": "username=admin&password=password&Login=Login"},
    {"action": "get", "url": B + P},
]
st, body = _execute_steps(c, s, B)
print(f"status={st} len={len(body)}")
print("OK" if st == 200 and "SQL" in body else "FAIL")
