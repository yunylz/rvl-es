#!/usr/bin/env python3
"""
TMD Reader - Reads and displays information from a Wii TMD file
"""

import struct
import argparse
import sys
import os

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

def get_signature_type_string(sig_type):
    """Get human-readable signature type"""
    if sig_type == TMD_CERT_RSA_4096:
        return "RSA-4096"
    elif sig_type == TMD_CERT_RSA_2048:
        return "RSA-2048"
    elif sig_type == TMD_CERT_ECC_B233:
        return "ECC-B233"
    return f"Unknown (0x{sig_type:08x})"

def get_region_string(region):
    """Get human-readable region"""
    regions = {
        0: "Japan",
        1: "America",
        2: "Europe",
        3: "Region Free",
        4: "Korea"
    }
    return regions.get(region, f"Unknown ({region})")

def parse_tmd_header(data, offset):
    """Parse TMD header structure"""
    header = {}
    
    # Skip padding (0x3C bytes)
    offset += 0x3C
    
    # Issuer (0x40 bytes)
    issuer = data[offset:offset+0x40]
    header['issuer'] = issuer.split(b'\x00')[0].decode('ascii', errors='ignore')
    offset += 0x40
    
    # Version info (4 bytes)
    header['version'] = data[offset]
    header['ca_crl_version'] = data[offset+1]
    header['signer_crl_version'] = data[offset+2]
    header['vwii'] = data[offset+3]
    offset += 4
    
    # IOS version (8 bytes)
    ios_full = struct.unpack('>Q', data[offset:offset+8])[0]
    header['ios_version'] = ios_full & 0xFF
    offset += 8
    
    # Title ID (8 bytes)
    title_id = struct.unpack('>Q', data[offset:offset+8])[0]
    header['title_id'] = title_id
    # Extract title code (last 4 bytes)
    title_code = data[offset+4:offset+8]
    header['title_code'] = title_code.decode('ascii', errors='ignore')
    offset += 8
    
    # Title type (4 bytes)
    header['title_type'] = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    
    # Group ID (2 bytes)
    header['group_id'] = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    
    # Padding (2 bytes)
    offset += 2
    
    # Region (2 bytes)
    header['region'] = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    
    # Ratings (0x10 bytes) - skip
    offset += 0x10
    
    # Padding (0xC bytes)
    offset += 0xC
    
    # IPC mask (0xC bytes) - skip
    offset += 0xC
    
    # Padding (0x12 bytes)
    offset += 0x12
    
    # Access rights (4 bytes)
    header['access_rights'] = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    
    # Title version (2 bytes)
    header['title_version'] = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    
    # Number of contents (2 bytes)
    header['num_contents'] = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    
    # Boot index (2 bytes)
    header['boot_index'] = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    
    # Padding (2 bytes)
    offset += 2
    
    return header, offset

def parse_tmd_content(data, offset):
    """Parse a single TMD content entry"""
    content = {}
    
    # Content ID (4 bytes)
    content['id'] = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    
    # Index (2 bytes)
    content['index'] = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    
    # Type (2 bytes)
    content['type'] = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    
    # Size (8 bytes)
    content['size'] = struct.unpack('>Q', data[offset:offset+8])[0]
    offset += 8
    
    # SHA-1 hash (0x14 bytes)
    content['sha1'] = data[offset:offset+0x14]
    offset += 0x14
    
    return content, offset

def read_tmd(filename, verbose=False):
    """Read and parse a TMD file"""
    try:
        with open(filename, 'rb') as f:
            data = f.read()
        
        offset = 0
        
        # Read signature type (4 bytes)
        sig_type = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        
        sig_size = get_signature_size(sig_type)
        if sig_size is None:
            print(f"Error: Unknown signature type: 0x{sig_type:08x}")
            return None
        
        # Skip signature
        offset += sig_size
        
        # Parse header
        header, offset = parse_tmd_header(data, offset)
        header['signature_type'] = sig_type
        
        # Parse contents
        contents = []
        for i in range(header['num_contents']):
            content, offset = parse_tmd_content(data, offset)
            contents.append(content)
        
        return {'header': header, 'contents': contents}
        
    except Exception as e:
        print(f"Error reading TMD: {e}")
        return None

def print_tmd_info(tmd_data, show_contents=False):
    """Print TMD information in a readable format"""
    header = tmd_data['header']
    contents = tmd_data['contents']
    
    print("=" * 60)
    print("TMD Information")
    print("=" * 60)
    print(f"Title ID:        {header['title_id']:016x} ({header['title_code']})")
    print(f"Title Version:   {header['title_version']}")
    print(f"IOS Version:     {header['ios_version']}")
    print(f"Region:          {get_region_string(header['region'])} ({header['region']})")
    print(f"Signature Type:  {get_signature_type_string(header['signature_type'])}")
    print(f"Issuer:          {header['issuer']}")
    print(f"Content Count:   {header['num_contents']}")
    print(f"Boot Index:      {header['boot_index']}")
    
    # Access rights
    access = header['access_rights']
    access_flags = []
    if access & 1:
        access_flags.append("AHBPROT")
    if access & 2:
        access_flags.append("DVD")
    print(f"Access Rights:   {' | '.join(access_flags) if access_flags else 'None'} (0x{access:08x})")
    
    if show_contents:
        print("\n" + "=" * 60)
        print("Contents")
        print("=" * 60)
        for i, content in enumerate(contents):
            print(f"\nContent {i}:")
            print(f"  Index:   {content['index']}")
            print(f"  ID:      {content['id']:08x}")
            print(f"  Type:    {content['type']:04x}")
            print(f"  Size:    {content['size']} bytes")
            print(f"  SHA-1:   {content['sha1'].hex()}")

def print_create_command(tmd_data, tmd_filename):
    """Print a tmdcreate.py command that would recreate this TMD"""
    header = tmd_data['header']
    
    # Determine signature type flag
    sig_type_map = {
        TMD_CERT_RSA_4096: 0,
        TMD_CERT_RSA_2048: 1,
        TMD_CERT_ECC_B233: 2
    }
    sig_flag = sig_type_map.get(header['signature_type'], 1)
    
    # Get directory of TMD file
    tmd_dir = os.path.dirname(os.path.abspath(tmd_filename))
    
    print("\n" + "=" * 60)
    print("Recreate with tmdcreate.py")
    print("=" * 60)
    print(f"./tmdcreate.py \\")
    print(f"  -t {header['title_id']:016x} \\")
    print(f"  -v {header['title_version']} \\")
    print(f"  -i {header['ios_version']} \\")
    print(f"  -r {header['region']} \\")
    print(f"  -b {header['boot_index']} \\")
    print(f"  -s {sig_flag} \\")
    print(f"  -o output.tmd \\")
    
    # Check if content files exist in the same directory
    content_files = []
    for content in tmd_data['contents']:
        content_file = f"{content['id']:08x}.app"
        full_path = os.path.join(tmd_dir, content_file)
        if os.path.exists(full_path):
            content_files.append(content_file)
    
    if len(content_files) == len(tmd_data['contents']):
        # All content files exist in the same directory
        print(f"  {tmd_dir}/")
    else:
        # List individual content files
        for content in tmd_data['contents']:
            print(f"  {content['id']:08x}.app \\")
        print()
        print("# Note: Replace with actual .app file paths")

def main():
    parser = argparse.ArgumentParser(description='Read and display Wii TMD file information')
    parser.add_argument('tmd', help='TMD file to read')
    parser.add_argument('-c', '--contents', action='store_true', help='Show detailed content information')
    parser.add_argument('-C', '--create-command', action='store_true', help='Show tmdcreate.py command to recreate this TMD')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.tmd):
        print(f"Error: File not found: {args.tmd}")
        return 1
    
    # Read TMD
    tmd_data = read_tmd(args.tmd)
    if tmd_data is None:
        return 1
    
    # Print information
    print_tmd_info(tmd_data, show_contents=args.contents)
    
    # Print create command if requested
    if args.create_command:
        print_create_command(tmd_data, args.tmd)
    
    return 0

if __name__ == '__main__':
    sys.exit(main())