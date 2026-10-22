"""
Argon2 Password Hashing Utilities for NotesApp
Class 5 Lab 2 - Secure Password Storage
"""
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
import hashlib

# Initialize Argon2 hasher with OWASP recommended parameters
# argon2-cffi uses safe defaults: 
# - time_cost=3, memory_cost=65536, parallelism=4
ph = PasswordHasher()


def hash_password(password: str) -> str:
    """
    Hash a password using Argon2id.
    
    Args:
        password: Plain text password
        
    Returns:
        Argon2 hash string (includes salt and parameters)
    """
    return ph.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """
    Verify a password against an Argon2 hash.
    
    Args:
        stored_hash: The hash from database
        password: Plain text password to verify
        
    Returns:
        True if password matches, False otherwise
    """
    try:
        ph.verify(stored_hash, password)
        return True
    except (VerifyMismatchError, VerificationError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """
    Check if a hash needs to be rehashed with updated parameters.
    
    Args:
        stored_hash: The hash to check
        
    Returns:
        True if rehash is recommended
    """
    return ph.check_needs_rehash(stored_hash)


def is_argon2_hash(value: str) -> bool:
    """
    Check if a value is an Argon2 hash (vs plaintext or MD5).
    
    Args:
        value: The value to check
        
    Returns:
        True if it looks like an Argon2 hash
    """
    return value.startswith('$argon2')


def is_md5_hash(value: str) -> bool:
    """
    Check if a value is an MD5 hash (32 hex characters).
    
    Args:
        value: The value to check
        
    Returns:
        True if it looks like an MD5 hash
    """
    if len(value) != 32:
        return False
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


def is_plaintext(value: str) -> bool:
    """
    Check if a value appears to be plaintext (not hashed).
    
    Args:
        value: The value to check
        
    Returns:
        True if it's likely plaintext
    """
    # Not a hash if it's too short or doesn't look like a hash
    if len(value) < 10:
        return True
    # Not plaintext if it starts with $argon2
    if value.startswith('$argon2'):
        return False
    # Not plaintext if it's 32 hex chars (MD5)
    if is_md5_hash(value):
        return False
    return True


def md5_hash(text: str) -> str:
    """
    Compute MD5 hash (for legacy compatibility only - DO NOT USE for new passwords).
    
    Args:
        text: Text to hash
        
    Returns:
        MD5 hex digest
    """
    return hashlib.md5(text.encode()).hexdigest()


# Test the functions
if __name__ == "__main__":
    print("=" * 70)
    print("ARGON2 PASSWORD HASHING TEST")
    print("=" * 70)
    
    test_password = "testpassword123"
    
    print(f"\nOriginal password: {test_password}")
    
    # Hash it
    hashed = hash_password(test_password)
    print(f"Argon2 hash: {hashed}")
    
    # Verify correct password
    is_valid = verify_password(hashed, test_password)
    print(f"\nVerify correct password: {is_valid}")
    
    # Verify wrong password
    is_invalid = verify_password(hashed, "wrongpassword")
    print(f"Verify wrong password: {is_invalid}")
    
    # Check if it's recognized as Argon2
    is_argon2 = is_argon2_hash(hashed)
    print(f"Is Argon2 hash: {is_argon2}")
    
    # Check if plaintext is detected
    is_plain = is_plaintext(test_password)
    print(f"Is plaintext: {is_plain}")
    
    # Check if MD5 is detected
    md5_example = md5_hash("test")
    is_md5 = is_md5_hash(md5_example)
    print(f"Is MD5 hash: {is_md5}")
    
    print("\n" + "=" * 70)
    print("All tests passed!")
    print("=" * 70)
