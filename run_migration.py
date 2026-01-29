"""
Script to manually apply the project_number migration
"""

from sqlalchemy import create_engine, text
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get database URL
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost/threatmodel")

print("Connecting to database...")
engine = create_engine(DATABASE_URL)

print("Adding project_number column to threat_assessments table...")

try:
    with engine.connect() as conn:
        # Check if column already exists
        result = conn.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='threat_assessments' 
            AND column_name='project_number'
        """))
        
        if result.fetchone():
            print("✓ Column 'project_number' already exists!")
        else:
            # Add the column
            conn.execute(text("""
                ALTER TABLE threat_assessments 
                ADD COLUMN project_number VARCHAR(100)
            """))
            
            # Create index
            conn.execute(text("""
                CREATE INDEX ix_threat_assessments_project_number 
                ON threat_assessments (project_number)
            """))
            
            conn.commit()
            print("✓ Successfully added project_number column and index!")
            
except Exception as e:
    print(f"✗ Error: {e}")
    print("\nNote: If using SQLite or the database is not initialized,")
    print("the migration will be applied automatically when the app starts.")

print("\nMigration complete!")
