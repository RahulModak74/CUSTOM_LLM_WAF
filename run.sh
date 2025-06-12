#!/bin/bash

# run.sh - Run script for Nginx Security Server (Python)

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run setup.sh first"
    exit 1
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source venv/bin/activate

# Check if main.py exists
if [ ! -f "main.py" ]; then
    echo "❌ main.py not found"
    exit 1
fi

# Run the server with passed arguments
echo "🚀 Starting Nginx Security Server..."
python main.py "$@"
