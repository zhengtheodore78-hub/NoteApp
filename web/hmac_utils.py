"""
HMAC utilities for NotesApp grade export integrity protection.

Implements HMAC-SHA256 for protecting grades_export.csv from tampering.
Based on Class 4: Hashing, Integrity & Asymmetric Encryption.
"""
import hmac
import hashlib
import base64
import os

# Secret key for HMAC - in production, store this in environment variable
# This key must be kept secret and only known to the server
HMAC_KEY = os.environ.get(
    'HMAC_SECRET_KEY', 
    b'notesapp_hmac_secret_key_2024'  # Default for development
)


def compute_hmac(data: str) -> str:
    """
    Compute HMAC-SHA256 of the given data.
    
    Args:
        data: The string data to compute HMAC for (e.g., CSV content)
    
    Returns:
        Base64-encoded HMAC string (hex format for readability)
    """
    hmac_obj = hmac.new(HMAC_KEY if isinstance(HMAC_KEY, bytes) else HMAC_KEY.encode(), 
                        data.encode('utf-8'), 
                        hashlib.sha256)
    # Return as hex string for readability (like the slide's color strips)
    return hmac_obj.hexdigest()


def verify_hmac(data: str, provided_hmac: str) -> bool:
    """
    Verify that the provided HMAC matches the computed HMAC.
    
    Args:
        data: The original data string
        provided_hmac: The HMAC to verify against (hex format)
    
    Returns:
        True if HMAC matches, False otherwise
    """
    computed = compute_hmac(data)
    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(computed, provided_hmac)


def add_hmac_to_csv(csv_content: str) -> str:
    """
    Add HMAC to the end of CSV content as a comment line.
    
    Format (as shown in Class 4 slide):
        student,class,grade,comment
        alice,Math,18,good work
        bob,Math,9,late twice
        # HMAC: <hex_digest>
    
    Args:
        csv_content: The CSV content as a string
    
    Returns:
        CSV content with HMAC appended
    """
    hmac_hex = compute_hmac(csv_content)
    return f"{csv_content}\n# HMAC: {hmac_hex}"


def extract_hmac_from_csv(csv_content: str) -> tuple[str, str | None]:
    """
    Extract HMAC from CSV content and return (content_without_hmac, hmac).
    
    Args:
        csv_content: The CSV content with HMAC line
    
    Returns:
        Tuple of (csv_content_without_hmac, hmac_hex_or_None)
    """
    lines = csv_content.strip().split('\n')
    
    # Check if last line is HMAC comment
    if lines and lines[-1].startswith('# HMAC: '):
        hmac_hex = lines[-1].replace('# HMAC: ', '').strip()
        csv_without_hmac = '\n'.join(lines[:-1])
        return csv_without_hmac, hmac_hex
    
    # No HMAC found
    return csv_content, None


def verify_csv_integrity(csv_content: str) -> bool:
    """
    Verify the integrity of a CSV file with embedded HMAC.
    
    Args:
        csv_content: The CSV content with HMAC line
    
    Returns:
        True if HMAC is valid, False if invalid or no HMAC present
    """
    csv_without_hmac, provided_hmac = extract_hmac_from_csv(csv_content)
    
    if provided_hmac is None:
        return False
    
    return verify_hmac(csv_without_hmac, provided_hmac)


# Test the functions
if __name__ == "__main__":
    print("=" * 70)
    print("HMAC INTEGRITY PROTECTION TEST")
    print("=" * 70)
    
    # Example CSV content (like Class 4 slide)
    csv_data = """student,class,grade,comment
alice,Math,18,good work
bob,Math,9,late twice
carol,Math,16,excellent"""
    
    print("\nOriginal CSV:")
    print(csv_data)
    
    # Add HMAC
    csv_with_hmac = add_hmac_to_csv(csv_data)
    print("\n\nCSV with HMAC:")
    print(csv_with_hmac)
    
    # Verify integrity (should pass)
    is_valid = verify_csv_integrity(csv_with_hmac)
    print(f"\n\nIntegrity check (untampered): {'✓ PASSED' if is_valid else '✗ FAILED'}")
    
    # Tamper with the data
    tampered_csv = csv_with_hmac.replace('alice,Math,18', 'alice,Math,20')
    is_valid_tampered = verify_csv_integrity(tampered_csv)
    print(f"Integrity check (tampered - grade 18→20): {'✓ PASSED' if is_valid_tampered else '✗ FAILED'}")
    
    # Show HMAC comparison (like the slide's color strips)
    original_hmac = compute_hmac(csv_data)
    tampered_hmac = compute_hmac(tampered_csv.split('\n# HMAC:')[0])
    
    print(f"\n\nOriginal HMAC:  {original_hmac}")
    print(f"Tampered HMAC:  {tampered_hmac}")
    print(f"\nHMAC match: {original_hmac == tampered_hmac}")
    
    # Count matching characters (demonstrate avalanche effect)
    match_count = sum(1 for a, b in zip(original_hmac, tampered_hmac) if a == b)
    print(f"Matching characters: {match_count} / {len(original_hmac)}")
    
    print("\n" + "=" * 70)
    print("CONCLUSION: Changing even one character completely changes the HMAC!")
    print("=" * 70)
