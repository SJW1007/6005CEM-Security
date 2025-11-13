"""
Script to safely check and add email verification columns to the user table.
This script checks if columns exist before attempting to add them.
"""

import mysql.connector
from mysql.connector import Error

from config.database_config import get_database_connection

def check_column_exists(cursor, table_name, column_name):
    """Check if a column exists in a table."""
    try:
        cursor.execute(f"""
            SELECT COUNT(*) 
            FROM INFORMATION_SCHEMA.COLUMNS 
            WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = '{table_name}'
            AND COLUMN_NAME = '{column_name}'
        """)
        result = cursor.fetchone()
        return result[0] > 0
    except Error as e:
        print(f"Error checking column: {e}")
        return False

def add_column_safely(cursor, connection, table_name, column_name, column_definition):
    """Safely add a column if it doesn't exist."""
    if check_column_exists(cursor, table_name, column_name):
        print(f"✓ Column '{column_name}' already exists. Skipping.")
        return True
    
    try:
        print(f"Adding column '{column_name}'...")
        alter_query = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}"
        cursor.execute(alter_query)
        connection.commit()
        print(f"✓ Successfully added column '{column_name}'")
        return True
    except Error as e:
        print(f"✗ Error adding column '{column_name}': {e}")
        connection.rollback()
        return False

def main():
    """Main function to add email verification columns."""
    connection = None
    cursor = None
    
    try:
        # Connect to database
        print("Connecting to database...")
        connection = get_database_connection()
        cursor = connection.cursor()
        print("✓ Connected to database\n")
        
        # Check and add columns one by one
        columns_to_add = [
            ('email_verified', 'BOOLEAN DEFAULT FALSE COMMENT "Whether email is verified"'),
            ('verification_code', 'VARCHAR(10) NULL DEFAULT NULL COMMENT "Temporary verification code"'),
            ('verification_code_expires', 'DATETIME NULL DEFAULT NULL COMMENT "Expiration time for verification code"')
        ]
        
        print("Checking and adding email verification columns...\n")
        
        for column_name, column_def in columns_to_add:
            success = add_column_safely(cursor, connection, 'user', column_name, column_def)
            if not success:
                print(f"\n⚠ Failed to add column '{column_name}'. Please check the error above.")
                return
        
        print("\n✅ All email verification columns have been added successfully!")
        print("\nYou can now use email verification in your application.")
        
    except Error as e:
        print(f"\n✗ Database error: {e}")
        print("\nTroubleshooting tips:")
        print("1. Make sure MySQL server is running")
        print("2. Check database credentials in the script")
        print("3. Close all other connections to the database")
        print("4. Check if the 'user' table exists")
        
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
            print("\n✓ Database connection closed")

if __name__ == "__main__":
    main()

