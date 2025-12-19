#!/usr/bin/env python3
"""
TMD Creator - Creates a Title Metadata file for Wii content
"""

import struct
import hashlib
import argparse
import os
import sys

# Signature types
TMD_CERT_RSA_4096 = 0x00010000
TMD_CERT_RSA_2048 = 0x00010001
TMD_CERT_ECC_B233 = 0x00010002

# Signature sizes
TMD_RSA_4096_SIZE = 0x200
TMD_RSA_2048_SIZE = 0x100
TMD_ECC_B233_SIZE = 0x3C

def get_signature_size(sig_type):
    """Get the size of a signature based on type"""
    if sig_type == TMD_CERT_RSA_4096:
        return TMD_RSA_4096_SIZE
    elif sig_type == TMD_CERT_RSA_2048:
        return TMD_RSA_2048_SIZE
    elif sig_type == TMD_CERT_ECC_B233:
        return TMD_ECC_B233_SIZE
    return None

def calculate_file_sha1(filename):
    """Calculate SHA-1 hash of a file"""
    sha1 = hashlib.sha1()
    try:
        with open(filename, 'rb') as f:
            while chunk := f.read(8192):
                sha1.update(chunk)
        return sha1.digest()
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        return None

def create_tmd_header(title_id, title_version, ios_version, region, num_contents, boot_index, 
                      access_rights=0, title_type=1, group_id=0, ratings=None):
    """Create a TMD header structure"""
    # Based on the TMDHeader struct from tmd.h, this should be exactly the struct size
    header = bytearray()
    
    # Padding (0x3C bytes = 60 bytes)
    header.extend(b'\x00' * 0x3C)
    
    # Issuer (0x40 bytes = 64 bytes)
    issuer = b"Root-CA00000001-CP00000004"
    issuer_padded = issuer + b'\x00' * (0x40 - len(issuer))
    header.extend(issuer_padded)
    
    # Version (1 byte), ca_crl_version (1), signer_crl_version (1), vwii (1)
    header.extend(bytes([0, 0, 0, 0]))
    
    # IOS version (8 bytes)
    ios_full = 0x0000000100000000 | ios_version
    header.extend(struct.pack('>Q', ios_full))
    
    # Title ID (8 bytes)
    header.extend(struct.pack('>Q', title_id))
    
    # Title type (4 bytes)
    header.extend(struct.pack('>I', title_type))
    
    # Group ID (2 bytes)
    header.extend(struct.pack('>H', group_id))
    
    # Padding (2 bytes)
    header.extend(struct.pack('>H', 0))
    
    # Region (2 bytes)
    header.extend(struct.pack('>H', region))
    
    # Ratings (0x10 bytes = 16 bytes)
    if ratings:
        header.extend(ratings)
    else:
        header.extend(b'\x00' * 0x10)
    
    # Padding (0xC bytes = 12 bytes)
    header.extend(b'\x00' * 0xC)
    
    # IPC mask (0xC bytes = 12 bytes)
    header.extend(b'\x00' * 0xC)
    
    # Padding (0x12 bytes = 18 bytes)
    header.extend(b'\x00' * 0x12)
    
    # Access rights (4 bytes)
    header.extend(struct.pack('>I', access_rights))
    
    # Title version (2 bytes)
    header.extend(struct.pack('>H', title_version))
    
    # Number of contents (2 bytes)
    header.extend(struct.pack('>H', num_contents))
    
    # Boot index (2 bytes)
    header.extend(struct.pack('>H', boot_index))
    
    # Padding (2 bytes)
    header.extend(struct.pack('>H', 0))
    
    # Total should be exactly the TMDHeader struct size
    # Don't add extra padding - this is the exact header
    return bytes(header)

def create_tmd_content(content_id, index, content_type, size, sha1_hash):
    """Create a TMD content entry"""
    # TMDContent structure (0x24 bytes)
    content = bytearray(0x24)
    
    # Content ID (4 bytes)
    struct.pack_into('>I', content, 0, content_id)
    
    # Index (2 bytes)
    struct.pack_into('>H', content, 4, index)
    
    # Type (2 bytes)
    struct.pack_into('>H', content, 6, content_type)
    
    # Size (8 bytes)
    struct.pack_into('>Q', content, 8, size)
    
    # SHA-1 hash (0x14 bytes)
    content[16:36] = sha1_hash
    
    return bytes(content)

def get_app_files_from_folder(folder_path):
    """Get all .app files from a folder, sorted numerically by filename"""
    app_files = []
    try:
        for filename in os.listdir(folder_path):
            if filename.lower().endswith('.app'):
                app_files.append(os.path.join(folder_path, filename))
        
        # Sort by the numeric part of the filename (e.g., 00000000.app, 00000001.app)
        app_files.sort(key=lambda x: os.path.basename(x))
        
        return app_files
    except Exception as e:
        print(f"Error reading folder {folder_path}: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description='Create a Wii TMD (Title Metadata) file')
    parser.add_argument('contents', nargs='+', help='Content files (.app) or folder containing .app files')
    parser.add_argument('-o', '--output', default='title.tmd', help='Output TMD filename (default: title.tmd)')
    parser.add_argument('-t', '--titleid', default='0000000100000000', help='Title ID in hex (default: 0000000100000000)')
    parser.add_argument('-v', '--version', type=int, default=0, help='Title version (default: 0)')
    parser.add_argument('-i', '--ios', type=int, default=80, help='IOS version (default: 80)')
    parser.add_argument('-r', '--region', type=int, default=3, help='Region (0=JP, 1=US, 2=EU, 3=Free, 4=KR) (default: 3)')
    parser.add_argument('-b', '--boot', type=int, default=0, help='Boot content index (default: 0)')
    parser.add_argument('-s', '--sigtype', type=int, default=1, help='Signature type (0=RSA4096, 1=RSA2048, 2=ECC) (default: 1)')
    parser.add_argument('-a', '--access', type=int, default=0, help='Access rights (default: 0)')
    parser.add_argument('-T', '--titletype', type=int, default=1, help='Title type (default: 1)')
    parser.add_argument('-g', '--groupid', default='0', help='Group ID in hex (default: 0)')
    parser.add_argument('-R', '--ratings', help='Ratings as hex string (32 chars for 16 bytes, e.g., 800A808080808080808080808080800)')
    
    args = parser.parse_args()
    
    # Check if the first argument is a folder
    content_files = []
    if len(args.contents) == 1 and os.path.isdir(args.contents[0]):
        print(f"Reading .app files from folder: {args.contents[0]}")
        content_files = get_app_files_from_folder(args.contents[0])
        if content_files is None or len(content_files) == 0:
            print("Error: No .app files found in folder")
            return 1
        print(f"Found {len(content_files)} .app file(s)")
    else:
        content_files = args.contents
    
    # Parse title ID
    try:
        title_id = int(args.titleid, 16)
    except ValueError:
        print(f"Error: Invalid title ID: {args.titleid}")
        return 1
    
    # Parse group ID
    try:
        group_id = int(args.groupid, 16)
    except ValueError:
        print(f"Error: Invalid group ID: {args.groupid}")
        return 1
    
    # Parse ratings if provided
    ratings = None
    if args.ratings:
        try:
            if len(args.ratings) != 32:
                print(f"Error: Ratings must be exactly 32 hex characters (16 bytes)")
                return 1
            ratings = bytes.fromhex(args.ratings)
        except ValueError:
            print(f"Error: Invalid ratings hex string: {args.ratings}")
            return 1
    
    # Map signature type
    sig_type_map = {
        0: TMD_CERT_RSA_4096,
        1: TMD_CERT_RSA_2048,
        2: TMD_CERT_ECC_B233
    }
    
    if args.sigtype not in sig_type_map:
        print(f"Error: Invalid signature type: {args.sigtype}")
        return 1
    
    signature_type = sig_type_map[args.sigtype]
    sig_size = get_signature_size(signature_type)
    
    num_contents = len(content_files)
    
    print(f"Creating TMD with {num_contents} content(s)")
    print(f"Title ID: {title_id:016x}")
    print(f"Version: {args.version}")
    print(f"IOS: {args.ios}")
    print(f"Region: {args.region}")
    print(f"Title Type: {args.titletype}")
    print(f"Group ID: {group_id:04x}")
    print(f"Access Rights: {args.access}")
    print(f"Output: {args.output}")
    if ratings:
        print(f"Ratings: {ratings.hex()}")
    print()
    
    # Check all content files exist
    for content_file in content_files:
        if not os.path.exists(content_file):
            print(f"Error: Content file not found: {content_file}")
            return 1
    
    # Create TMD file
    try:
        with open(args.output, 'wb') as tmd_file:
            # Write signature type (4 bytes, big-endian)
            tmd_file.write(struct.pack('>I', signature_type))
            
            # Write dummy signature (all zeros)
            tmd_file.write(b'\x00' * sig_size)
            
            # Write TMD header
            header = create_tmd_header(
                title_id=title_id,
                title_version=args.version,
                ios_version=args.ios,
                region=args.region,
                num_contents=num_contents,
                boot_index=args.boot,
                access_rights=args.access,
                title_type=args.titletype,
                group_id=group_id,
                ratings=ratings
            )
            tmd_file.write(header)
            
            # Process each content file
            for i, content_file in enumerate(content_files):
                # Extract content ID from filename (e.g., "00000016.app" -> 0x16)
                basename = os.path.basename(content_file)
                filename_without_ext = os.path.splitext(basename)[0]
                
                try:
                    content_id = int(filename_without_ext, 16)
                except ValueError:
                    print(f"Warning: Could not parse content ID from filename '{basename}', using index {i}")
                    content_id = i
                
                print(f"Processing content {i}: {os.path.basename(content_file)}")
                
                # Get file size
                file_size = os.path.getsize(content_file)
                print(f"  Content ID: 0x{content_id:08x}")
                print(f"  Size: {file_size} bytes")
                
                # Calculate SHA-1
                sha1_hash = calculate_file_sha1(content_file)
                if sha1_hash is None:
                    return 1
                
                print(f"  SHA-1: {sha1_hash.hex()}")
                
                # Create content entry
                # Set content type based on content ID
                # ID 0x16 (22) = type 0x0001 (base file)
                # All others = type 0x4001 (DLC content)
                content_type = 0x0001 if content_id == 0x16 else 0x4001
                print(f"  Type: 0x{content_type:04x}")
                
                content = create_tmd_content(
                    content_id=content_id,
                    index=i,
                    content_type=content_type,
                    size=file_size,
                    sha1_hash=sha1_hash
                )
                
                # Write content entry
                tmd_file.write(content)
        
        print(f"\nTMD created successfully: {args.output}")
        print(f"You can verify it with: ./tmdparse {args.output}")
        return 0
        
    except Exception as e:
        print(f"Error creating TMD: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())