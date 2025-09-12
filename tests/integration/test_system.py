#!/usr/bin/env python3
"""
PurgeProof System Test

Simple test to verify core functionality without requiring elevated privileges.
"""

import sys
import os
from pathlib import Path

# Add wipeit to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'wipeit'))

try:
    from wipeit.core.device_utils import DeviceDetector
    from wipeit.core.wipe_engine import WipeEngine, SanitizationMethod
    from wipeit.core.verification import VerificationEngine
    from wipeit.core.crypto_utils import CryptoManager
    
    print("PurgeProof System Test")
    print("=" * 30)
    
    # Test crypto utilities
    print("\n1. Testing Crypto Utilities...")
    crypto = CryptoManager()
    print("   ✓ CryptoManager initialized")
    test_data = "Hello, PurgeProof!"
    hash_result = crypto.hash_data(test_data)
    print(f"   ✓ Hash test: {hash_result[:16]}...")
    print(f"   ✓ Available key pairs: {len(crypto.list_key_pairs())}")
    
    # Test device detector (without requiring elevation)
    print("\n2. Testing Device Detection...")
    detector = DeviceDetector()
    print(f"   ✓ Device detector initialized")
    print(f"   ✓ Platform: {detector.platform}")
    
    # Test wipe engine
    print("\n3. Testing Wipe Engine...")
    wipe_engine = WipeEngine()
    methods = [method.value for method in SanitizationMethod]
    print(f"   ✓ Available methods: {', '.join(methods)}")
    
    # Test verification engine
    print("\n4. Testing Verification Engine...")
    verifier = VerificationEngine()
    print(f"   ✓ Verification engine initialized")
    
    print("\n✅ All core components loaded successfully!")
    print("\nPurgeProof is ready for use.")
    print("\nTo run with GUI: python launcher.py --tkinter (requires admin)")
    print("To run CLI: python launcher.py --cli")
    print("To list devices: python launcher.py --cli --list (requires admin)")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
except Exception as e:
    print(f"❌ Test error: {e}")
