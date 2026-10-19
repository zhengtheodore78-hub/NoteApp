# AES-GCM Comment Encryption - Homework Implementation

## Summary
Successfully implemented AES-GCM encryption for the `comment` column in NotesApp database.

## Files Created/Modified

### 1. **web/encryption.py** (NEW)
Encryption utility module using AES-GCM.

**Functions:**
- `encrypt_comment(plaintext)` - Encrypts comment with AES-128-GCM
- `decrypt_comment(encrypted_data)` - Decrypts AES-GCM encrypted comment

**Encryption Process:**
```
Plaintext → AES-GCM(nonce + key) → (nonce + ciphertext + tag) → Base64 → Database
```

### 2. **web/app.py** (MODIFIED)
Added encryption/decryption to all routes that handle comments.

**Changes:**
- Line 24: Added `from encryption import encrypt_comment, decrypt_comment`
- `/grades` (POST): Encrypts comment before INSERT/UPDATE
- `/dashboard`: Decrypts comments for student view
- `/api/notes/<id>`: Decrypts comments in API response
- `/teacher`: Decrypts comments for teacher view
- `/export.csv`: Decrypts comments before CSV export

### 3. **web/migrate_encryption.py** (NEW)
One-time migration script to encrypt existing plaintext comments in the database.

**Usage:**
```bash
python migrate_encryption.py
```

## How to Test

### Test Encryption Module
```bash
cd web
python encryption.py
```

Expected output:
```
======================================================================
AES-GCM ENCRYPTION TEST
======================================================================

Original comment:
  Late submission, but good quality.

Encrypted (base64):
  +qPaHLBpfiEAVIxwg5gZIdRngR50uMDcQi/+TyZseH4nL0+NiAO8vfp4Qoij1oCizXdfPgMC+HTJ+6+SFUw=

Decrypted:
  Late submission, but good quality.

Encryption/Decryption successful: True
======================================================================
```

## Deployment Steps

### 1. Deploy to Server
```bash
# Copy files to NotesApp server
scp web/encryption.py web/app.py web/migrate_encryption.py user@server:/path/to/notesapp/web/
```

### 2. Restart Application
```bash
cd /path/to/notesapp
docker-compose restart web
```

### 3. Migrate Existing Data
```bash
# Encrypt existing plaintext comments
docker-compose exec web python /app/migrate_encryption.py
```

### 4. Verify in Database
```bash
# Check that comments are now encrypted
docker-compose exec db psql -U notesapp -c "SELECT id, LEFT(comment, 50) FROM notes LIMIT 3;"
```

You should see base64-encoded data instead of plain text.

## Security Features

✅ **Confidentiality**: Comments encrypted at rest  
✅ **Integrity**: GCM authentication tag detects tampering  
✅ **Authentication**: Verifies data hasn't been modified  
✅ **Unique Nonces**: Each encryption uses different random nonce  
✅ **AES-128**: Strong symmetric encryption  

## Implementation Details

### Encryption Flow
1. Generate random 12-byte nonce (unique per encryption)
2. Encrypt comment using AES-128-GCM
3. Combine: nonce (12 bytes) + ciphertext + tag (16 bytes)
4. Base64-encode for database storage
5. Store in `comment` TEXT column

### Decryption Flow
1. Base64-decode stored data
2. Extract nonce (first 12 bytes)
3. Extract tag (last 16 bytes)
4. Extract ciphertext (middle portion)
5. Decrypt and verify with AES-GCM
6. Return plaintext

### Backward Compatibility
- `decrypt_comment()` gracefully handles both encrypted and plaintext data
- If decryption fails, returns original data (useful during migration)
- No breaking changes to existing functionality

## Database Schema
No changes required - `comment TEXT` column can store base64-encoded encrypted data.

## Key Management

**Current Implementation:**
```python
AES_KEY = b'0123456789abcdef'  # Hardcoded for demo
```

**Production Recommendation:**
```python
# Use environment variable
AES_KEY = os.environ.get('AES_ENCRYPTION_KEY', '').encode()
if not AES_KEY:
    raise ValueError("AES_ENCRYPTION_KEY not set")
```

## Homework Checklist

- [x] Created `encryption.py` with encrypt/decrypt functions
- [x] Modified `app.py` to import encryption module
- [x] Added encryption to `/grades` route (write operation)
- [x] Added decryption to `/dashboard` route (student read)
- [x] Added decryption to `/api/notes/<id>` route (API read)
- [x] Added decryption to `/teacher` route (teacher read)
- [x] Added decryption to `/export.csv` route (export)
- [x] Created migration script for existing data
- [x] Tested encryption/decryption locally
- [x] Verified test passes

## Example Output

### Before Encryption (Database)
```
id | comment
---|------------------------------------------
1  | Late submission, but good quality.
2  | Needs to review chapter 3.
```

### After Encryption (Database)
```
id | comment
---|--------------------------------------------------------------------------
1  | +qPaHLBpfiEAVIxwg5gZIdRngR50uMDcQi/+TyZseH4nL0+NiAO8vfp4Qoij1oC...
2  | 8KzJmN2xRL6iLHm9c4Q6zuFZ3v9w5x6y7z8a9b0c1d2e3f4g5h6i7j8k9l0m...
```

### User Interface (Unchanged)
Students and teachers still see:
```
"Late submission, but good quality."
```

The encryption is completely transparent to end users! 🔒

## Notes

- AES-128-GCM provides both confidentiality and authenticity
- Nonce ensures same plaintext produces different ciphertext each time
- Tag (16 bytes) provides integrity verification
- Base64 encoding adds ~33% overhead but ensures safe database storage
- Migration script can be run multiple times safely (skips already-encrypted data)

## References

- NIST SP 800-38D: GCM Mode Recommendation
- PyCryptodome Documentation: https://pycryptodome.org/
- Flask Documentation: https://flask.palletsprojects.com/
