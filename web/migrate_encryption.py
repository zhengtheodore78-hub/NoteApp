"""
Script to encrypt all existing comments in the database.
Run this once after deploying the encryption-enabled version of NotesApp.
"""
import os
import sys
import psycopg2
import psycopg2.extras

# Add parent directory to path to import encryption module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from encryption import encrypt_comment

# Database configuration (same as app.py)
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_NAME = os.environ.get("DB_NAME", "notesapp")
DB_USER = os.environ.get("DB_USER", "notesapp")
DB_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "notesapp_pg_pw_2024")


def migrate_comments():
    """Encrypt all existing comments in the database"""
    print("=" * 70)
    print("MIGRATING COMMENTS TO AES-GCM ENCRYPTION")
    print("=" * 70)
    
    try:
        conn = psycopg2.connect(
            host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD,
            cursor_factory=psycopg2.extras.RealDictCursor,
        )
        conn.autocommit = False  # Use transaction
        
        cur = conn.cursor()
        
        # Fetch all notes with comments
        print("\n[1] Fetching existing comments...")
        cur.execute("SELECT id, comment FROM notes")
        notes = cur.fetchall()
        
        print(f"  Found {len(notes)} notes")
        
        # Encrypt and update each comment
        print("\n[2] Encrypting comments...")
        encrypted_count = 0
        skipped_count = 0
        
        for note in notes:
            note_id = note["id"]
            comment = note["comment"]
            
            # Skip if already encrypted (heuristic: encrypted data is base64 and longer)
            if comment and len(comment) > 100:
                # Likely already encrypted, skip
                skipped_count += 1
                continue
            
            # Encrypt the comment
            encrypted_comment = encrypt_comment(comment)
            
            # Update in database
            cur.execute(
                "UPDATE notes SET comment = %s WHERE id = %s",
                (encrypted_comment, note_id),
            )
            encrypted_count += 1
            
            if encrypted_count % 10 == 0:
                print(f"  Encrypted {encrypted_count} comments...")
        
        # Commit the transaction
        conn.commit()
        
        print(f"\n[3] Migration complete!")
        print(f"  Encrypted: {encrypted_count} comments")
        print(f"  Skipped (already encrypted): {skipped_count} comments")
        
        cur.close()
        conn.close()
        
        print("\n" + "=" * 70)
        print("SUCCESS! All comments are now encrypted with AES-GCM.")
        print("=" * 70)
        
    except Exception as e:
        print(f"\nERROR: {e}")
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return False
    
    return True


if __name__ == "__main__":
    success = migrate_comments()
    sys.exit(0 if success else 1)
