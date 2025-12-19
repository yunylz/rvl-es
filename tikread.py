#!/usr/bin/env python3
"""
Ticket Reader - Reads and displays information from a Wii ticket file
"""

import struct
import argparse
import sys
import os

# Signature types
SIG_RSA_4096 = 0x00010000
SIG_RSA_2048 = 0x00010001
SIG_ECC_B233 = 0x00010002

# Signature sizes
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

def get_signature_type_string(sig_type):
    """Get human-readable signature type"""
    if sig_type == SIG_RSA_4096:
        return "RSA-4096"
    elif sig_type == SIG_RSA_2048:
        return "RSA-2048"
    elif sig_type == SIG_ECC_B233:
        return "ECC-B233"
    return f"Unknown (0x{sig_type:08x})"

def parse_ticket(data):
    """Parse a Wii ticket structure"""
    ticket = {}
    offset = 0
    
    # Signature type (4 bytes)
    sig_type = struct.unpack('>I', data[offset:offset+4])[0]
    ticket['signature_type'] = sig_type
    offset += 4
    
    sig_size = get_signature_size(sig_type)
    if sig_size is None:
        print(f"Error: Unknown signature type: 0x{sig_type:08x}")
        return None
    
    # Signature (variable size)
    ticket['signature'] = data[offset:offset+sig_size]
    offset += sig_size
    
    # Padding (0x3C bytes)
    offset += 0x3C
    
    # Issuer (0x40 bytes)
    issuer = data[offset:offset+0x40]
    ticket['issuer'] = issuer.split(b'\x00')[0].decode('ascii', errors='ignore')
    offset += 0x40
    
    # ECDH data (0x3C bytes)
    ticket['ecdh_data'] = data[offset:offset+0x3C]
    offset += 0x3C
    
    # Padding (0x3 bytes)
    offset += 0x3
    
    # Title key (encrypted, 0x10 bytes)
    ticket['title_key_enc'] = data[offset:offset+0x10]
    offset += 0x10
    
    # Unknown (1 byte)
    offset += 1
    
    # Ticket ID (8 bytes)
    ticket['ticket_id'] = struct.unpack('>Q', data[offset:offset+8])[0]
    offset += 8
    
    # Console ID (4 bytes)
    ticket['console_id'] = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    
    # Title ID (8 bytes)
    ticket['title_id'] = struct.unpack('>Q', data[offset:offset+8])[0]
    offset += 8
    
    # Unknown (2 bytes)
    offset += 2
    
    # Title version (2 bytes)
    ticket['title_version'] = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    
    # Titles mask (4 bytes)
    ticket['titles_mask'] = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    
    # Permit mask (4 bytes)
    ticket['permit_mask'] = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    
    # Export allowed (1 byte)
    ticket['export_allowed'] = data[offset]
    offset += 1
    
    # Key index (1 byte) - which common key to use
    ticket['key_index'] = data[offset]
    offset += 1
    
    # Unknown (0x30 bytes)
    offset += 0x30
    
    # Access permissions (0x40 bytes)
    ticket['access_permissions'] = data[offset:offset+0x40]
    offset += 0x40
    
    # Padding (2 bytes)
    offset += 2
    
    # Ticket limits (8 limits, each 8 bytes)
    ticket['limits'] = []
    for i in range(8):
        limit_type = struct.unpack('>I', data[offset:offset+4])[0]
        limit_usage = struct.unpack('>I', data[offset+4:offset+8])[0]
        ticket['limits'].append({'type': limit_type, 'usage': limit_usage})
        offset += 8
    
    return ticket

def get_key_name(key_index):
    """Get the common key name"""
    key_names = {
        0: "Wii Common Key",
        1: "Korean Wii Key",
        2: "vWii Common Key"
    }
    return key_names.get(key_index, f"Unknown ({key_index})")

def print_ticket_info(ticket):
    """Print ticket information in a readable format"""
    print("=" * 60)
    print("Ticket Information")
    print("=" * 60)
    print(f"Title ID:        {ticket['title_id']:016x}")
    print(f"Title Version:   {ticket['title_version']}")
    print(f"Ticket ID:       {ticket['ticket_id']:016x}")
    print(f"Console ID:      {ticket['console_id']:08x}")
    print(f"Signature Type:  {get_signature_type_string(ticket['signature_type'])}")
    print(f"Issuer:          {ticket['issuer']}")
    print(f"Key Index:       {ticket['key_index']} ({get_key_name(ticket['key_index'])})")
    print(f"Export Allowed:  {'Yes' if ticket['export_allowed'] else 'No'}")
    print(f"Titles Mask:     0x{ticket['titles_mask']:08x}")
    print(f"Permit Mask:     0x{ticket['permit_mask']:08x}")
    print(f"\nEncrypted Title Key:")
    print(f"  {ticket['title_key_enc'].hex()}")
    
    # Check for non-zero limits
    has_limits = False
    for i, limit in enumerate(ticket['limits']):
        if limit['type'] != 0 or limit['usage'] != 0:
            if not has_limits:
                print(f"\nTicket Limits:")
                has_limits = True
            print(f"  Limit {i}: Type=0x{limit['type']:08x}, Usage=0x{limit['usage']:08x}")
    
    if not has_limits:
        print(f"\nTicket Limits:   None")

def print_create_command(ticket, tik_filename):
    """Print a tikcreate.py command that would recreate this ticket"""
    print("\n" + "=" * 60)
    print("Recreate with tikcreate.py (when available)")
    print("=" * 60)
    print(f"./tikcreate.py \\")
    print(f"  -t {ticket['title_id']:016x} \\")
    print(f"  -v {ticket['title_version']} \\")
    print(f"  -k {ticket['title_key_enc'].hex()} \\")
    print(f"  -i {ticket['key_index']} \\")
    print(f"  -c {ticket['console_id']:08x} \\")
    print(f"  -T {ticket['ticket_id']:016x} \\")
    print(f"  -s {0 if ticket['signature_type'] == SIG_RSA_4096 else 1 if ticket['signature_type'] == SIG_RSA_2048 else 2} \\")
    print(f"  -o output.tik")

def main():
    parser = argparse.ArgumentParser(description='Read and display Wii ticket file information')
    parser.add_argument('ticket', help='Ticket file (.tik) to read')
    parser.add_argument('-C', '--create-command', action='store_true', help='Show tikcreate.py command to recreate this ticket')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.ticket):
        print(f"Error: File not found: {args.ticket}")
        return 1
    
    # Read ticket
    try:
        with open(args.ticket, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading ticket: {e}")
        return 1
    
    # Parse ticket
    ticket = parse_ticket(data)
    if ticket is None:
        return 1
    
    # Print information
    print_ticket_info(ticket)
    
    # Print create command if requested
    if args.create_command:
        print_create_command(ticket, args.ticket)
    
    return 0

if __name__ == '__main__':
    sys.exit(main())