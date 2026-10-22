"""
Test script for HMAC grade export protection.

Demonstrates the Class 4 security feature:
- Export CSV with HMAC
- Tamper detection
"""
import sys
import os

# Add web directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hmac_utils import compute_hmac, verify_hmac, add_hmac_to_csv, verify_csv_integrity

def test_hmac_protection():
    print("=" * 70)
    print("NOTESAPP GRADES EXPORT - HMAC PROTECTION TEST")
    print("=" * 70)
    print("\nBased on Class 4: Hashing, Integrity & Asymmetric Encryption")
    print("-" * 70)
    
    # Example grades CSV (like Class 4 slide)
    original_csv = """student,class,grade,comment
alice,Math,14,good work
bob,Math,9,late twice
carol,Math,16,excellent"""
    
    print("\n📊 ORIGINAL GRADES CSV:")
    print(original_csv)
    
    # Step 1: Add HMAC to CSV
    csv_with_hmac = add_hmac_to_csv(original_csv)
    print("\n\n📦 EXPORTED CSV WITH HMAC:")
    print(csv_with_hmac)
    
    # Step 2: Verify integrity (should pass)
    is_valid = verify_csv_integrity(csv_with_hmac)
    print(f"\n\n✅ INTEGRITY CHECK (ORIGINAL FILE): {'PASSED ✓' if is_valid else 'FAILED ✗'}")
    
    # Step 3: Tamper with the grade (like Eve in Class 4)
    print("\n\n🔓 SIMULATING EVE'S ATTACK...")
    print("   Eve intercepts the file and changes alice's grade from 14 → 18")
    
    tampered_csv = original_csv.replace('alice,Math,14', 'alice,Math,18')
    tampered_csv_with_old_hmac = add_hmac_to_csv(tampered_csv)
    # Keep the original HMAC to simulate Eve's attack
    tampered_csv_with_old_hmac = tampered_csv_with_old_hmac.split('\n# HMAC:')[0] + '\n# HMAC: ' + compute_hmac(original_csv)
    
    print("\n   Tampered CSV:")
    print(tampered_csv_with_old_hmac)
    
    # Step 4: Verify tampered file (should fail)
    is_valid_tampered = verify_csv_integrity(tampered_csv_with_old_hmac)
    print(f"\n❌ INTEGRITY CHECK (TAMPERED FILE): {'PASSED ✓' if is_valid_tampered else 'FAILED ✗'}")
    
    if not is_valid_tampered:
        print("\n   ️  CHECK FAILED - Tampering detected!")
        print("   Server rejects this file - Eve's attack is blocked!")
    
    # Step 5: Show avalanche effect
    print("\n\n🔬 AVALANCHE EFFECT DEMONSTRATION:")
    original_hmac = compute_hmac(original_csv)
    tampered_hmac_only = compute_hmac(tampered_csv)
    
    print(f"\n   Original HMAC:  {original_hmac}")
    print(f"   Tampered HMAC:  {tampered_hmac_only}")
    
    # Count matching characters
    match_count = sum(1 for a, b in zip(original_hmac, tampered_hmac_only) if a == b)
    total_chars = len(original_hmac)
    
    print(f"\n   Matching characters: {match_count} / {total_chars}")
    print(f"   Match percentage: {match_count/total_chars*100:.1f}%")
    
    if match_count < total_chars * 0.3:
        print("\n   🎯 AVALANCHE EFFECT CONFIRMED!")
        print("   Changing one grade (14→18) completely changes the HMAC!")
    
    print("\n" + "=" * 70)
    print("TEST COMPLETE")
    print("=" * 70)
    print("\nKey Takeaways from Class 4:")
    print("  ✓ A hash proves nothing changed")
    print("  ✓ An HMAC also proves WHO sent it (only server has the key)")
    print("  ✓ Eve can't forge a valid HMAC without the secret key")
    print("  ✓ SHA-256 avalanche effect: 1 bit change → ~50% bits flip")
    print("\n" + "=" * 70)


if __name__ == "__main__":
    test_hmac_protection()
