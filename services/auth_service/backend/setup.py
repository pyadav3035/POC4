#!/usr/bin/env python
"""
Quick setup script for Django Auth Service.

This script helps set up the Django authentication service quickly
for development and testing purposes.
"""

import os
import sys
import subprocess
import django
import shutil
from pathlib import Path

def run_command(command, description):
    """Run a shell command and handle errors."""
    print(f"\n🔄 {description}...")
    try:
        # Fix: Use shell=False and split command to prevent injection
        cmd_list = command.split() if isinstance(command, str) else command
        result = subprocess.run(cmd_list, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        if result.stdout:
            print(f"Output: {result.stdout.strip()}")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error during {description}")
        print(f"Error: {e.stderr}")
        return False
    return True

def setup_django():
    """Set up Django environment."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
    try:
        django.setup()
        print("✅ Django environment set up successfully")
        return True
    except Exception as e:
        print(f"❌ Error setting up Django: {e}")
        return False

def main():
    """Main setup function."""
    print("🚀 Setting up Django Authentication Service")
    print("=" * 50)
    
    # Change to the backend directory
    backend_dir = Path(__file__).parent
    os.chdir(backend_dir)
    print(f"📁 Working directory: {backend_dir}")
    
    # Check if virtual environment is activated
    if not hasattr(sys, 'real_prefix') and not (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("⚠️  Warning: Virtual environment not detected. Consider using a virtual environment.")
    
    # Install dependencies
    if not run_command(["pip", "install", "-r", "requirements.txt"], "Installing dependencies"):
        print("❌ Failed to install dependencies. Please check your Python environment.")
        return False
    
    # Create .env file if it doesn't exist
    if not os.path.exists('.env'):
        if os.path.exists('.env.example'):
            import shutil
            shutil.copy('.env.example', '.env')
            print("✅ Created .env file from template")
        else:
            print("⚠️  .env.example not found. Please create a .env file manually.")
    
    # Set up Django
    if not setup_django():
        return False
    
    # Run migrations
    if not run_command(["python", "manage.py", "makemigrations"], "Creating migrations"):
        return False
    
    if not run_command(["python", "manage.py", "migrate"], "Applying migrations"):
        return False
    
    # Create test users
    print("\n📝 Creating test users for development...")
    if run_command(["python", "manage.py", "create_test_users", "--password", "testpass123"], "Creating test users"):
        print("✅ Test users created successfully")
        print("   Username: testuser1, Email: testuser1@example.com")
        print("   Username: admin, Email: admin@example.com")
    
    # Collect static files (for production)
    run_command(["python", "manage.py", "collectstatic", "--noinput"], "Collecting static files")
    
    print("\n🎉 Setup completed successfully!")
    print("=" * 50)
    print("🚀 To start the development server, run:")
    print("   python manage.py runserver")
    print("\n📚 API Endpoints:")
    print("   POST /api/v1/auth/login/")
    print("   POST /api/v1/auth/logout/")
    print("   GET  /api/v1/auth/profile/")
    print("   POST /api/v1/auth/token/refresh/")
    print("\n🧪 To run tests:")
    print("   python manage.py test")
    print("\n📖 Check README.md for detailed usage examples")

if __name__ == "__main__":
    main()
