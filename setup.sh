#!/bin/bash

# setup.sh - Setup script for Nginx Security Server (Python)

echo "🔧 Setting up Nginx Security Server (Python)"
echo "=" * 45

# Check Python version
python_version=$(python3 --version 2>&1)
if [[ $? -eq 0 ]]; then
    echo "✅ Python found: $python_version"
else
    echo "❌ Python 3 not found. Please install Python 3.8+"
    exit 1
fi

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 not found. Please install pip3"
    exit 1
fi

echo "✅ pip3 found"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
    if [[ $? -eq 0 ]]; then
        echo "✅ Virtual environment created"
    else
        echo "❌ Failed to create virtual environment"
        exit 1
    fi
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "📚 Installing requirements..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    if [[ $? -eq 0 ]]; then
        echo "✅ Requirements installed successfully"
    else
        echo "❌ Failed to install requirements"
        exit 1
    fi
else
    echo "❌ requirements.txt not found"
    exit 1
fi

# Create security_modules directory if it doesn't exist
if [ ! -d "security_modules" ]; then
    echo "📁 Creating security_modules directory..."
    mkdir security_modules
fi

# Make scripts executable
chmod +x main.py
chmod +x test.py

echo ""
echo "🎉 Setup complete!"
echo ""
echo "🚀 To start the server:"
echo "   source venv/bin/activate"
echo "   python main.py [local|remote|debug|local-debug|remote-debug]"
echo ""
echo "🧪 To run tests:"
echo "   python test.py"
echo ""
echo "📖 Example usage:"
echo "   python main.py local-debug    # Local mode with debug"
echo "   python main.py remote         # Remote mode"
echo "   python main.py production     # Production mode"
