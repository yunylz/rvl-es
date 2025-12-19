#!/usr/bin/env python3
"""
Ticket Encrypt - Encrypts Wii content files using a ticket
Reverse of tikdecrypt - encrypts plain .app files for CDN distribution
"""

import struct
import argparse
import sys
import os
from Crypto.Cipher import AES

# Wii Common Keys (from tikdecrypt.c)
COMMON_KEYS = {
    0: bytes([0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7]),  # Wii Common Key
    1: bytes([0x63, 0xb8, 0x2b, 0xb4, 0xf4, 0x61, 0x4e, 0x2e, 0x13, 0xf2, 0xfe, 0xfb, 0xba, 0x4c, 0x9b, 0x7e]),  # Korean Wii Key
    2: bytes([0x30, 0xbf, 0xc7, 0x6e, 0x7c, 0x19, 0xaf, 0xbb, 0x23, 0x16, 0x33, 0x30, 0xce, 0xd7, 0xc2, 0x8d])   # vWii Common Key
}

# Signature types and sizes
SIG_RSA_4096 = 0x00010000
SIG_RSA_2048 = 0x00010001
SIG_ECC_B233 = 0x00010002

SIG_RSA_4096_SIZE = 0x200
SIG_RSA_2048_SIZE = 0x100
SIG_ECC_B233_SIZE = 0x3C

def get_signature_size(sig_type):
    """Get the size of a signature based on type"""
    if sig_type == SIG_RSA_4096:
        return SIG_RSA_4096_SIZE
    elif sig_type == SIG_RSA_2048:
        return SIG_RSA_2048_SIZE
    elif sig_type == SIG_ECC_B233:
        return SIG_ECC_B233_SIZE
    return None

def parse_ticket(data):
    """Parse a Wii ticket to extract the encrypted title key and other info"""
    offset = 0
    
    # Signature type (4 bytes)
    sig_type = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    
    sig_size = get_signature_size(sig_type)
    if sig_size is None:
        return None
    
    # Skip signature
    offset += sig_size
    
    # Padding (0x3C bytes)
    offset += 0x3C
    
    # Issuer (0x40 bytes)
    offset += 0x40
    
    # ECDH data (0x3C bytes)
    offset += 0x3C
    
    # Padding (0x3 bytes)
    offset += 0x3
    
    # Title key (encrypted, 0x10 bytes)
    title_key_enc = data[offset:offset+0x10]
    offset += 0x10
    
    # Unknown (1 byte)
    offset += 1
    
    # Ticket ID (8 bytes)
    ticket_id = struct.unpack('>Q', data[offset:offset+8])[0]
    offset += 8
    
    # Console ID (4 bytes)
    console_id = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    
    # Title ID (8 bytes)
    title_id = struct.unpack('>Q', data[offset:offset+8])[0]
    offset += 8
    
    # Unknown (2 bytes)
    offset += 2
    
    # Title version (2 bytes)
    title_version = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    
    # Titles mask (4 bytes)
    offset += 4
    
    # Permit mask (4 bytes)
    offset += 4
    
    # Export allowed (1 byte)
    export_allowed = data[offset]
    offset += 1
    
    # Key index (1 byte)
    key_index = data[offset]
    
    return {
        'title_key_enc': title_key_enc,
        'title_id': title_id,
        'key_index': key_index,
        'console_id': console_id,
        'ticket_id': ticket_id,
        'title_version': title_version
    }

def derive_title_key(ticket_info):
    """Decrypt the title key from the ticket"""
    # ALWAYS use Wii Common Key (index 0), ignore ticket key_index
    common_key = COMMON_KEYS[0]
    
    print(f"Using Wii Common Key (index 0) - ignoring ticket key_index {ticket_info['key_index']}")
    
    # Create IV from title_id (big-endian, 8 bytes)
    iv = struct.pack('>Q', ticket_info['title_id']) + b'\x00' * 8
    
    # Decrypt the title key using AES-CBC
    cipher = AES.new(common_key, AES.MODE_CBC, iv)
    title_key = cipher.decrypt(ticket_info['title_key_enc'])
    
    return title_key

def encrypt_content(title_key, content_index, data):
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
    parser = argparse.ArgumentParser(description='Encrypt Wii content files using a ticket')
    parser.add_argument('ticket', help='Ticket file (.tik)')
    parser.add_argument('content', help='Plain content file (.app) to encrypt')
    parser.add_argument('index', type=int, help='Content index (0, 1, 2, ...)')
    parser.add_argument('-o', '--output', help='Output encrypted file (default: <input>.enc)')
    
    args = parser.parse_args()
    
    # Determine output filename
    if args.output:
        output_file = args.output
    else:
        output_file = args.content + '.enc'
    
    # Read ticket
    try:
        with open(args.ticket, 'rb') as f:
            ticket_data = f.read()
    except Exception as e:
        print(f"Error reading ticket: {e}")
        return 1
    
    # Parse ticket
    print(f"Parsing ticket...")
    ticket_info = parse_ticket(ticket_data)
    if ticket_info is None:
        print("Error: Failed to parse ticket")
        return 1
    
    print(f"Title ID: {ticket_info['title_id']:016x}")
    print(f"Key Index: {ticket_info['key_index']}")
    
    # Derive title key
    print(f"Deriving title key...")
    title_key = derive_title_key(ticket_info)
    if title_key is None:
        return 1
    
    print(f"Title Key: {title_key.hex()}")
    
    # Read content file
    try:
        with open(args.content, 'rb') as f:
            content_data = f.read()
    except Exception as e:
        print(f"Error reading content file: {e}")
        return 1
    
    print(f"Content size: {len(content_data)} bytes")
    print(f"Content index: {args.index}")
    
    # Encrypt content
    print(f"Encrypting content...")
    encrypted_data = encrypt_content(title_key, args.index, content_data)
    
    # Write encrypted content
    try:
        with open(output_file, 'wb') as f:
            f.write(encrypted_data)
    except Exception as e:
        print(f"Error writing output file: {e}")
        return 1
    
    print(f"Encrypted content written to: {output_file}")
    print(f"Encrypted size: {len(encrypted_data)} bytes")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())