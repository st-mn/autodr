#!/bin/bash

echo "=================================================="
echo "  AUTODR + Shuffle Integration Setup"
echo "=================================================="
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Docker and Docker Compose found"
echo ""

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env
    echo "⚠️  Please edit .env file with your configuration"
    echo ""
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p models
mkdir -p data
mkdir -p shuffle_workflows
mkdir -p logs

# Install Python requirements
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

echo ""
echo "🐳 Starting Shuffle services with Docker Compose..."
docker-compose up -d

echo ""
echo "⏳ Waiting for services to start (30 seconds)..."
sleep 30

# Check service health
echo ""
echo "🔍 Checking service health..."

if curl -s http://localhost:3001 > /dev/null; then
    echo "✅ Shuffle Frontend: http://localhost:3001"
else
    echo "⚠️  Shuffle Frontend not responding yet"
fi

if curl -s http://localhost:5001/api/v1/workflows > /dev/null 2>&1; then
    echo "✅ Shuffle Backend: http://localhost:5001"
else
    echo "⚠️  Shuffle Backend not responding yet"
fi

if curl -s http://localhost:5000/health > /dev/null 2>&1; then
    echo "✅ AUTODR API: http://localhost:5000"
else
    echo "⚠️  AUTODR API not responding yet"
fi

if curl -s http://localhost:8080/health > /dev/null 2>&1; then
    echo "✅ ML Service: http://localhost:8080"
else
    echo "⚠️  ML Service not responding yet"
fi

echo ""
echo "=================================================="
echo "  Setup Complete!"
echo "=================================================="
echo ""
echo "Next Steps:"
echo "1. Access Shuffle UI: http://localhost:3001"
echo "2. Create admin account (first time)"
echo "3. Generate API key in Settings"
echo "4. Update .env file with API key"
echo "5. Run: python import_shuffle_workflows.py"
echo "6. Update .env with workflow IDs"
echo "7. Run: python autodr.py"
echo ""
echo "📖 See QUICKSTART_SHUFFLE.md for detailed guide"
echo "=================================================="
