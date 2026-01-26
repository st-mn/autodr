#!/bin/bash
# IRIS Integration Setup Script for AUTODR

set -e

echo "=================================================="
echo "  IRIS Case Management Integration Setup"
echo "=================================================="
echo ""

# Check if .env file exists
if [ ! -f .env ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    echo "✓ .env file created"
else
    echo "✓ .env file already exists"
fi

# Verify docker-compose
echo ""
echo "Checking Docker Compose..."
if ! command -v docker-compose &> /dev/null; then
    echo "✗ Docker Compose not found. Please install Docker Compose."
    exit 1
fi
echo "✓ Docker Compose found"

# Start IRIS services
echo ""
echo "Starting IRIS services..."
docker-compose up -d iris-db iris-rabbitmq
echo "⏳ Waiting for database and message queue to initialize (30s)..."
sleep 30

docker-compose up -d iris-web iris-worker
echo "⏳ Waiting for IRIS web application to start (45s)..."
sleep 45

# Check IRIS health
echo ""
echo "Checking IRIS health..."
if curl -s http://localhost:8000/login > /dev/null; then
    echo "✓ IRIS web interface is accessible"
else
    echo "✗ IRIS web interface not responding"
    echo "  Check logs: docker-compose logs iris-web"
    exit 1
fi

# Display access information
echo ""
echo "=================================================="
echo "  IRIS Setup Complete!"
echo "=================================================="
echo ""
echo "Access IRIS Web Interface:"
echo "  URL: http://localhost:8000"
echo "  Default Username: administrator@iris.local"
echo "  Default Password: password"
echo ""
echo "⚠️  IMPORTANT: Change default password immediately!"
echo ""
echo "Next Steps:"
echo "  1. Login to IRIS web interface"
echo "  2. Navigate to: User Menu → My Settings → API Keys"
echo "  3. Generate a new API key"
echo "  4. Add to .env file: IRIS_API_KEY=your_key_here"
echo "  5. Restart AUTODR services: docker-compose restart autodr-api"
echo ""
echo "Documentation:"
echo "  - IRIS Integration Guide: iris/IRIS_INTEGRATION.md"
echo "  - IRIS API Docs: http://localhost:8000/api/v2/swagger"
echo "  - IRIS User Guide: https://docs.dfir-iris.org/"
echo ""
echo "Verify Integration:"
echo "  python3 -c \"from iris.iris_integration import IrisIntegration; IrisIntegration()\""
echo ""
echo "=================================================="
