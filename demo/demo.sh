#!/usr/bin/env bash
# BugBounty Bot demo
#
# DVWA + Juice Shop + bWAPP + WebGoat + BugBounty Bot
#
# 사용:
#   1. .env 파일에 H1_API_KEY, OPENAI_API_KEY 설정
#   2. ./demo.sh
#
# 결과:
#   - DVWA: http://localhost:8081
#   - Juice Shop: http://localhost:3000
#   - bWAPP: http://localhost:8082
#   - WebGoat: http://localhost:8083/WebGoat
#   - BugBounty Bot: http://localhost:8500

set -euo pipefail
cd "$(dirname "$0")/.."

echo "=========================================="
echo "  BugBounty Bot Demo"
echo "=========================================="

# Check .env
if [ ! -f .env ]; then
    echo "[!] .env not found. Creating template..."
    cat > .env << EOF
H1_API_KEY=your-hackerone-api-key
OPENAI_API_KEY=your-openai-api-key
EOF
    echo "[i] Edit .env with your API keys"
fi

# Start Docker Compose
echo "[*] Starting Docker Compose..."
docker-compose up -d

echo ""
echo "=========================================="
echo "  Services started:"
echo "=========================================="
echo "  DVWA:         http://localhost:8081"
echo "  Juice Shop:   http://localhost:3000"
echo "  bWAPP:        http://localhost:8082"
echo "  WebGoat:      http://localhost:8083/WebGoat"
echo "  BugBounty:    http://localhost:8500"
echo ""
echo "  Wait 30 seconds for services to start..."
echo "  Then open http://localhost:8500 in your browser"
echo ""
echo "  To stop: docker-compose down"
echo "=========================================="
