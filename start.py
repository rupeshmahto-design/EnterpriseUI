#!/usr/bin/env python3
"""
Railway startup script with error handling
"""
import os
import sys
from pathlib import Path

def main():
    print("🚀 Starting EnterpriseUI deployment...")
    
    # Check critical environment variables
    print("\n📋 Checking environment variables...")
    required_vars = {
        "DATABASE_URL": os.getenv("DATABASE_URL"),
        "PORT": os.getenv("PORT", "8000")
    }
    
    optional_vars = {
        "ANTHROPIC_API_KEY": os.getenv("ANTHROPIC_API_KEY"),
        "SECRET_KEY": os.getenv("SECRET_KEY"),
        "ENVIRONMENT": os.getenv("ENVIRONMENT", "production")
    }
    
    for key, value in required_vars.items():
        if value:
            print(f"✅ {key}: {'*' * 10} (set)")
        else:
            print(f"❌ {key}: NOT SET")
    
    for key, value in optional_vars.items():
        if value:
            print(f"✅ {key}: {'*' * 10} (set)")
        else:
            print(f"⚠️  {key}: NOT SET (optional but recommended)")
    
    # Check if frontend is built
    print("\n🎨 Checking frontend build...")
    dist_dir = Path(__file__).parent / "dist"
    if dist_dir.exists() and (dist_dir / "index.html").exists():
        print(f"✅ Frontend built at: {dist_dir}")
        assets_dir = dist_dir / "assets"
        if assets_dir.exists():
            asset_count = len(list(assets_dir.glob("*")))
            print(f"   Found {asset_count} asset files")
    else:
        print("⚠️  Frontend not built - will serve API only")
    
    # Check database connection
    print("\n🗄️  Checking database connection...")
    try:
        from database import engine
        from models import Base
        with engine.connect() as conn:
            print("✅ Database connection successful")
        
        # Create tables if they don't exist
        print("\n📊 Ensuring database tables exist...")
        Base.metadata.create_all(bind=engine)
        print("✅ Database tables ready")
        
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        print("   Will attempt to continue anyway...")
    
    # Start the server
    port = int(os.getenv("PORT", "8000"))
    print(f"\n🌐 Starting server on port {port}...")
    print(f"   Environment: {os.getenv('ENVIRONMENT', 'production')}")
    
    os.execvp("uvicorn", [
        "uvicorn",
        "api:app",
        "--host", "0.0.0.0",
        "--port", str(port),
        "--workers", "1",
        "--log-level", "info"
    ])

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n💥 Startup failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
