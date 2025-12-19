#!/usr/bin/env python3
"""
Create Encrypted TMD - Encrypts .app files and creates TMD with encrypted file hashes
"""

import struct
import hashlib
import argparse
import os
import sys
from Crypto.Cipher import AES

# Wii Common Key
COMMON_KEY = bytes([0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7])

def encrypt_content(data, title_key, content_index):
    """Encrypt content data using the title key and content index"""
    # Create IV from content index (big-endian, 2 bytes, padded to 16 bytes)
    iv = struct.pack('>H', content_index) + b'\x00' * 14
    
    # Pad data to 16-byte blocks (AES block size)
    padding_needed = (16 - (len(data) % 16)) % 16
    padded_data = data + b'\x00' * padding_needed
    
    # Encrypt using AES-CBC
    cipher = AES.new(title_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(padded_data)
    
    return encrypted_data

def main():
    parser = argparse.ArgumentParser(description='Encrypt .app files and create TMD with encrypted hashes')
    parser.add_argument('ticket', help='Ticket file (.tik)')
    parser.add_argument('app_files', nargs='+', help='Plain .app files to encrypt')
    parser.add_argument('-o', '--output-dir', default='encrypted_output', help='Output directory')
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Read ticket and get title key
    print("Reading ticket...")
    with open(args.ticket, 'rb') as f:
        ticket_data = f.read()
    
    # Parse ticket to get encrypted title key
    offset = 4 + 0x100 + 0x3C + 0x40 + 0x3C + 0x3  # Skip to title_key
    title_key_enc = ticket_data[offset:offset+0x10]
    
    # Check if it's the fake key
    if title_key_enc == bytes.fromhex('476f747461476574536f6d6542656572'):
        print("Using fake title key 'GottaGetSomeBeer' directly")
        title_key = title_key_enc
    else:
        print("Decrypting title key with Wii Common Key")
        # Get title ID
        offset = 4 + 0x100 + 0x3C + 0x40 + 0x3C + 0x3 + 0x10 + 1 + 8 + 4
        title_id = struct.unpack('>Q', ticket_data[offset:offset+8])[0]
        
        # Decrypt title key
        iv = struct.pack('>Q', title_id) + b'\x00' * 8
        cipher = AES.new(COMMON_KEY, AES.MODE_CBC, iv)
        title_key = cipher.decrypt(title_key_enc)
    
    print(f"Title Key: {title_key.hex()}")
    print()
    
    # Process each app file
    encrypted_files = []
    for i, app_file in enumerate(args.app_files):
        basename = os.path.basename(app_file)
        filename_without_ext = os.path.splitext(basename)[0]
        
        try:
            content_id = int(filename_without_ext, 16)
        except ValueError:
            content_id = i
        
        print(f"Processing {basename}...")
        print(f"  Content ID: 0x{content_id:08x}")
        print(f"  Content Index: {i}")
        
        # Read plain file
        with open(app_file, 'rb') as f:
            plain_data = f.read()
        
        plain_size = len(plain_data)
        plain_hash = hashlib.sha1(plain_data).hexdigest()
        
        print(f"  Plain size: {plain_size} bytes")
        print(f"  Plain SHA-1: {plain_hash}")
        
        # Encrypt
        encrypted_data = encrypt_content(plain_data, title_key, i)
        encrypted_hash = hashlib.sha1(encrypted_data).hexdigest()
        
        print(f"  Encrypted size: {len(encrypted_data)} bytes")
        print(f"  Encrypted SHA-1: {encrypted_hash}")
        
        # Save encrypted file
        output_path = os.path.join(args.output_dir, f"{content_id:08x}")
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
        
        print(f"  Saved: {output_path}")
        
        encrypted_files.append({
            'id': content_id,
            'index': i,
            'size': plain_size,  # TMD should have plain size
            'sha1': encrypted_hash,  # But encrypted hash!
            'filename': f"{content_id:08x}"
        })
        print()
    
    # Print tmdcreate.py command
    print("=" * 60)
    print("Now create TMD with these encrypted hashes:")
    print("=" * 60)
    print()
    print("IMPORTANT: You need to manually update tmdcreate.py to use these hashes!")
    print()
    for ef in encrypted_files:
        print(f"Content {ef['index']}: ID={ef['id']:08x}, SHA-1={ef['sha1']}")
    print()
    print("Or upload these encrypted files to your CDN:")
    for ef in encrypted_files:
        print(f"  {args.output_dir}/{ef['filename']}")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())