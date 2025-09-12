#!/usr/bin/env python3
"""Quick performance test"""
import time
import os

start = time.time()
data = os.urandom(1024*1024)  # 1MB
with open('temp_test.bin', 'wb') as f:
    f.write(data)
with open('temp_test.bin', 'rb') as f:
    read_data = f.read()
os.remove('temp_test.bin')
elapsed = time.time() - start
print(f'✅ 1MB file I/O test: {elapsed:.3f} seconds')
