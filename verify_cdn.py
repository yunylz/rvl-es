#!/usr/bin/env python3
"""
Verify CDN - Downloads TMD and content from CDN and checks if hash matches encrypted or decrypted version
"""

import struct
import hashlib
import sys
import requests
from Crypto.Cipher import AES

# Wii Common Key
COMMON_KEY = bytes([0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7])

def download_file(url):
    """Download a file from URL"""
    print(f"Downloading: {url}")
    try:
        response = requests.get(url)
        response.raise_for_status()
        print(f"  Downloaded: {len(response.content)} bytes")
        return response.content
    except Exception as e:
        print(f"  Error: {e}")
        return None

def parse_tmd_content(tmd_data, content_index):
    """Parse TMD to get content info"""
    offset = 0
    
    # Signature type (4 bytes)
    sig_type = struct.unpack('>I', tmd_data[offset:offset+4])[0]
    offset += 4
    
    # Get signature size
    sig_size = 0x100 if sig_type == 0x00010001 else 0x200
    offset += sig_size
    
    # Skip TMD header (0xE0 bytes based on our previous calculation)
    offset += 0xE0
    
    # Read content entries (each is 0x24 = 36 bytes)
    for i in range(100):  # Max 100 contents
        if offset + 36 > len(tmd_data):
            break
        
        content_id = struct.unpack('>I', tmd_data[offset:offset+4])[0]
        content_index_val = struct.unpack('>H', tmd_data[offset+4:offset+6])[0]
        content_type = struct.unpack('>H', tmd_data[offset+6:offset+8])[0]
        content_size = struct.unpack('>Q', tmd_data[offset+8:offset+16])[0]
        content_sha1 = tmd_data[offset+16:offset+36]
        
        if content_index_val == content_index:
            return {
                'id': content_id,
                'index': content_index_val,
                'type': content_type,
                'size': content_size,
                'sha1': content_sha1
            }
        
        offset += 36
    
    return None

def decrypt_content(data, title_key, content_index):
    """Decrypt content using AES-CBC"""
    # Create IV from content index
    iv = struct.pack('>H', content_index) + b'\x00' * 14
    
    # Decrypt
    cipher = AES.new(title_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data)
    
    return decrypted

def main():
    base_url = "http://oss-auth.thecheese.io/oss/ccs/download/0001000573453345"
    title_id = 0x0001000573453345
    
    # Download TMD
    tmd_data = download_file(f"{base_url}/tmd.2")
    if tmd_data is None:
        return 1
    
    # Download content 00000016
    content_data = download_file(f"{base_url}/00000016")
    if content_data is None:
        return 1
    
    print()
    print("=" * 60)
    
    # Parse TMD to get expected hash for content index 0
    content_info = parse_tmd_content(tmd_data, 0)
    if content_info is None:
        print("Error: Could not find content index 0 in TMD")
        return 1
    
    print(f"Content Info from TMD:")
    print(f"  ID: {content_info['id']:08x}")
    print(f"  Index: {content_info['index']}")
    print(f"  Type: {content_info['type']:04x}")
    print(f"  Size: {content_info['size']} bytes")
    print(f"  Expected SHA-1: {content_info['sha1'].hex()}")
    print()
    
    # Check hash of encrypted content
    encrypted_hash = hashlib.sha1(content_data).digest()
    print(f"Downloaded content (encrypted):")
    print(f"  Size: {len(content_data)} bytes")
    print(f"  SHA-1: {encrypted_hash.hex()}")
    
    if encrypted_hash == content_info['sha1']:
        print(f"  ✅ MATCH! TMD contains hash of ENCRYPTED content")
        return 0
    else:
        print(f"  ❌ No match")
    
    print()
    
    # Try decrypting with fake title key "GottaGetSomeBeer"
    fake_title_key = bytes.fromhex('476f747461476574536f6d6542656572')
    
    print(f"Trying to decrypt with fake title key 'GottaGetSomeBeer'...")
    decrypted_data = decrypt_content(content_data, fake_title_key, 0)
    
    # Trim to expected size
    decrypted_data = decrypted_data[:content_info['size']]
    
    decrypted_hash = hashlib.sha1(decrypted_data).digest()
    print(f"Decrypted content:")
    print(f"  Size: {len(decrypted_data)} bytes")
    print(f"  SHA-1: {decrypted_hash.hex()}")
    
    if decrypted_hash == content_info['sha1']:
        print(f"  ✅ MATCH! TMD contains hash of DECRYPTED content")
        print(f"  Title key 'GottaGetSomeBeer' works!")
        return 0
    else:
        print(f"  ❌ No match")
    
    print()
    
    # Try decrypting title key with common key
    print(f"Trying to decrypt 'GottaGetSomeBeer' title key with Wii Common Key...")
    iv = struct.pack('>Q', title_id) + b'\x00' * 8
    cipher = AES.new(COMMON_KEY, AES.MODE_CBC, iv)
    real_title_key = cipher.decrypt(fake_title_key)
    
    print(f"  Decrypted title key: {real_title_key.hex()}")
    
    decrypted_data2 = decrypt_content(content_data, real_title_key, 0)
    decrypted_data2 = decrypted_data2[:content_info['size']]
    decrypted_hash2 = hashlib.sha1(decrypted_data2).digest()
    
    print(f"Decrypted with real title key:")
    print(f"  SHA-1: {decrypted_hash2.hex()}")
    
    if decrypted_hash2 == content_info['sha1']:
        print(f"  ✅ MATCH! TMD contains hash of DECRYPTED content")
        print(f"  Title key needs to be decrypted first!")
        return 0
    else:
        print(f"  ❌ No match")
    
    print()
    print("=" * 60)
    print("Summary: Could not determine if content is encrypted or not")
    print("The TMD hash doesn't match either encrypted or decrypted version")
    
    return 1

if __name__ == '__main__':
    sys.exit(main())