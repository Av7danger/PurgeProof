#!/usr/bin/env python3
"""
PurgeProof Minimal CLI Test

Test basic functionality without initializing components that require elevation.
"""

import sys
import os

# Add wipeit to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'wipeit'))

def test_basic_functionality():
    """Test basic functionality without requiring elevation."""
    print("PurgeProof Minimal CLI Test")
    print("=" * 30)
    
    # Test imports
    print("\n1. Testing Core Imports...")
    try:
        from wipeit.core.crypto_utils import CryptoManager
        print("   ✓ CryptoManager imported")
        
        from wipeit.core.wipe_engine import SanitizationMethod
        print("   ✓ SanitizationMethod imported")
        
        # Test crypto functionality
        print("\n2. Testing Crypto Functions...")
        crypto = CryptoManager()
        test_hash = crypto.hash_data("test data")
        print(f"   ✓ Hash function: {test_hash[:32]}...")
        
        key_pairs = crypto.list_key_pairs()
        print(f"   ✓ Key pairs available: {len(key_pairs)}")
        
        # Test sanitization methods
        print("\n3. Testing Sanitization Methods...")
        methods = list(SanitizationMethod)
        print(f"   ✓ Available methods: {len(methods)}")
        for i, method in enumerate(methods, 1):
            print(f"      {i}. {method.value}")
            
        print("\n✅ All basic tests passed!")
        print("\nTo test device operations, run as administrator:")
        print("   python launcher.py --tkinter")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        return False

def main():
    """Main function."""
    success = test_basic_functionality()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
