"""8c: multi-step 검증 (login → protected page)."""
import sys
sys.path.insert(0, '.')
from core.config import Config
from core.models import Asset
from exploit.executor import ExploitExecutor

B = "http://localhost:8081"
P = "/vulnerabilities/sqli/"

ex = ExploitExecutor(Config.load())
s = [
    {"action": "login", "url": B + "/login.php",
     "body": "username=admin&password=password&Login=Login"},
    {"action": "get", "url": B + P},
]
result = ex.execute_steps(s, B)
st = result.get("status", 0)
body = result.get("body_snippet", "")
print(f"status={st} len={len(body)}")
print("OK" if st == 200 and "SQL" in body else "FAIL")
