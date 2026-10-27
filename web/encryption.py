"""
Encryption utilities for NotesApp using AES-GCM
"""
import os
import base64

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# AES key for comment encryption.
# Loaded from the environment (set in .env, which is gitignored) so that no key
# material is ever hard-coded in source. Key length 16/24/32 bytes -> AES-128/192/256.
_aes_key = os.environ.get("AES_KEY")
if not _aes_key:
    raise RuntimeError(
        "AES_KEY is not set. Put it in .env (for docker compose) "
        "or export AES_KEY before running."
    )
AES_KEY = _aes_key.encode("utf-8")



def encrypt_comment(plaintext):
    """
    Encrypt a comment using AES-GCM.
    Returns: base64 encoded string containing nonce + ciphertext + tag
    """
    if not plaintext:
        return plaintext
    
    # Generate a random nonce (12 bytes for GCM)
    nonce = get_random_bytes(12)
    
    # Create cipher and encrypt
    cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    
    # Combine nonce + ciphertext + tag (so we can decrypt later)
    encrypted_data = nonce + ciphertext + tag
    
    # Encode as base64 for database storage
    return base64.b64encode(encrypted_data).decode('utf-8')


def decrypt_comment(encrypted_data):
    """
    Decrypt an AES-GCM encrypted comment.
    Input: base64 encoded string containing nonce + ciphertext + tag
    Returns: decrypted plaintext string
    """
    if not encrypted_data:
        return encrypted_data
    
    try:
        # Decode from base64
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Extract nonce (first 12 bytes), tag (last 16 bytes), and ciphertext
        nonce = encrypted_bytes[:12]
        tag = encrypted_bytes[-16:]
        ciphertext = encrypted_bytes[12:-16]
        
        # Decrypt and verify
        cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return plaintext.decode('utf-8')
    
    except Exception as e:
        # If decryption fails (e.g., data was not encrypted), return as-is
        # This helps with backward compatibility during migration
        return encrypted_data


# Test the functions
if __name__ == "__main__":
    test_comment = "Late submission, but good quality."
    
    print("=" * 70)
    print("AES-GCM ENCRYPTION TEST")
    print("=" * 70)
    
    print(f"\nOriginal comment:")
    print(f"  {test_comment}")
    
    encrypted = encrypt_comment(test_comment)
    print(f"\nEncrypted (base64):")
    print(f"  {encrypted}")
    
    decrypted = decrypt_comment(encrypted)
    print(f"\nDecrypted:")
    print(f"  {decrypted}")
    
    print(f"\nEncryption/Decryption successful: {decrypted == test_comment}")
    print("=" * 70)
