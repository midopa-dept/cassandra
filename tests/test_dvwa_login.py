"""DVWA login + DB reset test."""
import httpx
from scanner.login import login, get_authenticated_client
from core.models import Asset

asset = Asset(base_url='http://localhost:8081')
client = get_authenticated_client(asset)
print('cookies:', dict(client.cookies))
r = client.get('http://localhost:8081/')
print('GET /:', r.status_code, r.headers.get('location', ''))
has_logout = 'logout' in r.text.lower()
has_vuln = 'vulnerabilities' in r.text.lower()
print('has logout:', has_logout)
print('has vulnerabilities:', has_vuln)

r2 = client.get('http://localhost:8081/vulnerabilities/sqli/')
print('GET sqli:', r2.status_code, r2.headers.get('location', ''))
has_id = 'id' in r2.text.lower()
has_submit = 'submit' in r2.text.lower()
print('has id field:', has_id)
print('has Submit:', has_submit)
