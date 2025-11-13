"""
Password Migration Script

⚠️ IMPORTANT: BACKUP YOUR DATABASE BEFORE RUNNING THIS SCRIPT! ⚠️

This script migrates all plaintext passwords in the database to bcrypt hashes.
It will:
1. Read all user passwords from the database
2. Check if they are already hashed (bcrypt hashes start with $2b$)
3. Hash any plaintext passwords using bcrypt
4. Update the database with the hashed passwords

Usage:
    python migrations/migrate_passwords.py

Database Configuration:
    Update the connection parameters below to match your database settings.
"""

import mysql.connector
import sys
import os

# Add parent directory to path to import password_utils
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from security.password_utils import hash_password, verify_password
from config.database_config import get_database_connection


def is_bcrypt_hash(password: str) -> bool:
    """
    Check if a password is already a bcrypt hash.
    Bcrypt hashes start with $2a$, $2b$, or $2y$ and are 60 characters long.
    """
    if not password:
        return False
    return (password.startswith('$2a$') or 
            password.startswith('$2b$') or 
            password.startswith('$2y$')) and len(password) == 60


def migrate_passwords():
    """
    Migrate all plaintext passwords to bcrypt hashes.
    """
    print("=" * 60)
    print("PASSWORD MIGRATION SCRIPT")
    print("=" * 60)
    print("\n⚠️  WARNING: Make sure you have backed up your database! ⚠️")
    print("\nThis script will hash all plaintext passwords in the database.")
    
    # Confirm before proceeding
    response = input("\nDo you want to continue? (yes/no): ")
    if response.lower() != 'yes':
        print("Migration cancelled.")
        return
    
    try:
        # Connect to database
        print("\nConnecting to database...")
        database = get_database_connection()
        cursor = database.cursor()
        print("✓ Connected to database")
        
        # Fetch all users
        print("\nFetching all users from database...")
        cursor.execute('''SELECT user_id, user_email, user_password FROM user''')
        users = cursor.fetchall()
        print(f"✓ Found {len(users)} users")
        
        # Track migration statistics
        already_hashed = 0
        migrated = 0
        errors = 0
        
        print("\nStarting migration...")
        print("-" * 60)
        
        for user_id, user_email, user_password in users:
            try:
                # Check if password is already hashed
                if is_bcrypt_hash(user_password):
                    already_hashed += 1
                    print(f"✓ User {user_id} ({user_email}): Already hashed")
                else:
                    # Hash the plaintext password
                    hashed_password = hash_password(user_password)
                    
                    # Update the database
                    cursor.execute('''UPDATE user SET user_password=%s WHERE user_id=%s''',
                                 (hashed_password, user_id))
                    
                    # Verify the hash works
                    if verify_password(user_password, hashed_password):
                        migrated += 1
                        print(f"✓ User {user_id} ({user_email}): Migrated successfully")
                    else:
                        errors += 1
                        print(f"✗ User {user_id} ({user_email}): Verification failed!")
                        
            except Exception as e:
                errors += 1
                print(f"✗ User {user_id} ({user_email}): Error - {str(e)}")
        
        # Commit all changes
        if migrated > 0:
            database.commit()
            print("\n" + "-" * 60)
            print("✓ All changes committed to database")
        
        # Print summary
        print("\n" + "=" * 60)
        print("MIGRATION SUMMARY")
        print("=" * 60)
        print(f"Total users processed: {len(users)}")
        print(f"Already hashed: {already_hashed}")
        print(f"Successfully migrated: {migrated}")
        print(f"Errors: {errors}")
        print("=" * 60)
        
        if errors == 0:
            print("\n✓ Migration completed successfully!")
        else:
            print(f"\n⚠️  Migration completed with {errors} error(s). Please review the output above.")
        
        # Close database connection
        cursor.close()
        database.close()
        print("\n✓ Database connection closed")
        
    except mysql.connector.Error as e:
        print(f"\n✗ Database error: {str(e)}")
        print("Please check your database connection parameters.")
    except Exception as e:
        print(f"\n✗ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    migrate_passwords()

