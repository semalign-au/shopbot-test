#!/usr/bin/env bash
set -e

echo "═══ Shopbot Production Setup ═══"

sudo apt update
sudo apt install -y python3 python3-venv python3-pip \
    postgresql postgresql-contrib postgresql-client

sudo systemctl enable postgresql
sudo systemctl start postgresql

DB_PASS=$(openssl rand -hex 16)

sudo -u postgres psql <<EOF
DO \$\$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'shopbot') THEN
      CREATE ROLE shopbot LOGIN PASSWORD '${DB_PASS}';
   END IF;
END
\$\$;
EOF

sudo -u postgres psql <<EOF
SELECT 'CREATE DATABASE shopbot OWNER shopbot'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'shopbot')\gexec
EOF

sudo -u postgres psql -c "ALTER USER shopbot WITH PASSWORD '${DB_PASS}';"
sudo -u postgres psql -c "ALTER USER shopbot CREATEDB;"

echo ""
echo "════════════════════════════════════════"
echo "✅ Database ready"
echo ""
echo "   DATABASE_URL=postgresql://shopbot:${DB_PASS}@127.0.0.1:5432/shopbot"
echo ""
echo "   → Paste this into .env"
echo "════════════════════════════════════════"

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

mkdir -p backups

# Create service user
sudo useradd -r -s /bin/bash -d /opt/shopbot shopbot 2>/dev/null || true
sudo chown -R shopbot:shopbot /opt/shopbot 2>/dev/null || true

echo ""
echo "✅ Setup complete. Next:"
echo "  1. Fill .env"
echo "  2. chmod 600 .env"
echo "  3. source venv/bin/activate && python bot.py  (test — Ctrl+C)"
echo "  4. Install systemd:"
echo "     sudo cp shopbot.service /etc/systemd/system/"
echo "     sudo systemctl daemon-reload"
echo "     sudo systemctl enable --now shopbot"