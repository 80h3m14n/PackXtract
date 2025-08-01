#!/usr/bin/env python3
"""
PackXtract - Unified CLI for packing, obfuscation, unpacking, and deobfuscation operations.

This script provides a single interface to:
- Pack/obfuscate Python files and binaries (packer.py functionality)
- Light obfuscation for Python files (text_obfuscator.py functionality)
- Unpack/deobfuscate packed files (unpacker.py functionality)
"""

import argparse
import sys
import os
from pathlib import Path

# Import the existing modules
from packer import UltimateObfuscator
from text_obfuscator import StealthObfuscator
from unpacker import extract_keys_from_loader, extract_encrypted_from_loader, unpack, detect_binary_type, normalize_blob, sha256_digest


def pack_command(args):
    """Handle pack/obfuscate operations using UltimateObfuscator."""
    print(f"[*] Packing/obfuscating: {args.input}")

    # Convert custom key/iv from hex if provided
    custom_key = None
    custom_iv = None

    if args.key:
        try:
            custom_key = bytes.fromhex(args.key)
        except ValueError:
            print("[-] Error: Key must be a valid hex string")
            sys.exit(1)

    if args.iv:
        try:
            custom_iv = bytes.fromhex(args.iv)
        except ValueError:
            print("[-] Error: IV must be a valid hex string")
            sys.exit(1)

    obfuscator = UltimateObfuscator(args.input)
    obfuscator.obfuscate(args.output, custom_key, custom_iv)

    packed_file = args.output
    if not packed_file:
        # Determine default output name based on input
        input_path = Path(args.input)
        if input_path.suffix == '.py':
            packed_file = f"output/packed_{input_path.stem}_loader.py"
        else:
            packed_file = f"output/packed_executable_loader.py"

    print(f"[+] Packed output saved to: {packed_file}")

    # Create standalone executable if requested
    if args.standalone:
        try:
            from standalone_builder import create_standalone_executable, check_pyinstaller, install_pyinstaller

            # Check if PyInstaller is available
            if not check_pyinstaller():
                print("[*] PyInstaller not found, installing...")
                if not install_pyinstaller():
                    print(
                        "[-] Failed to install PyInstaller. Skipping standalone creation.")
                    return

            packed_path = Path(packed_file)
            standalone_dir = packed_path.parent / "standalone"

            print(f"[*] Creating standalone executable...")
            executable_path = create_standalone_executable(
                packed_path,
                output_dir=standalone_dir,
                console=args.console if hasattr(args, 'console') else False
            )
            print(f"[+] Standalone executable created: {executable_path}")

        except Exception as e:
            print(f"[-] Failed to create standalone executable: {e}")
            print(f"[*] You can manually convert later using:")
            print(f"    python standalone_builder.py {packed_file}")


def light_obfuscate_command(args):
    """Handle light obfuscation operations using StealthObfuscator."""
    print(f"[*] Light obfuscating: {args.input}")

    if not args.input.lower().endswith('.py'):
        print("[-] Error: Light obfuscation only supports Python (.py) files")
        sys.exit(1)

    if not os.path.isfile(args.input):
        print(f"[-] Error: File not found: {args.input}")
        sys.exit(1)

    obfuscator = StealthObfuscator(args.input)
    obfuscator.obfuscate()
    print("[+] Light obfuscation completed")


def unpack_command(args):
    """Handle unpack/deobfuscate operations using enhanced unpacker functionality."""
    print(f"[*] Unpacking: {args.input}")

    in_path = Path(args.input)
    out_path = Path(args.output)

    if not in_path.exists():
        print(f"[-] Input file {in_path} does not exist.")
        sys.exit(1)

    print(f"[*] Reading input from {in_path}")

    raw = in_path.read_text(errors="ignore")

    # Try to extract custom keys from the loader
    custom_keys = extract_keys_from_loader(raw)
    if custom_keys:
        key, iv = custom_keys
        print(
            f"[*] Extracted custom keys from loader: KEY={len(key)} bytes, IV={len(iv)} bytes")
    else:
        key, iv = None, None
        print("[*] No custom keys found, using default keys")

    # Extract encrypted payload
    encrypted = extract_encrypted_from_loader(raw)
    if encrypted:
        print("[*] Detected loader script; extracted _encrypted blob.")
        encrypted = normalize_blob(encrypted)
    else:
        print("[*] No embedded _encrypted assignment found; treating file as raw blob.")
        encrypted = normalize_blob(raw)

    try:
        payload = unpack(encrypted, key, iv)
    except Exception as e:
        print(f"[-] Failed to unpack payload: {e}")
        if custom_keys:
            print(
                "[-] Custom keys were extracted but decryption failed. The payload may be corrupted.")
        else:
            print(
                "[-] Default keys failed. This file may have been packed with custom keys.")
        sys.exit(1)

    btype = detect_binary_type(payload)
    digest = sha256_digest(payload)
    print(f"[+] Detected binary type: {btype}")
    print(f"[+] SHA256: {digest}")

    if not args.skip_write:
        out_path.write_bytes(payload)
        print(f"[+] Written unpacked payload to {out_path}")
        if os.name != 'nt':
            out_path.chmod(0o755)
    else:
        print("[*] --skip-write provided; not writing output.")

    if args.print_type:
        print(f"[i] Payload header (first 64 bytes): {payload[:64].hex()}")


def standalone_command(args):
    """Handle standalone executable creation using standalone_builder."""
    try:
        from standalone_builder import create_standalone_executable, batch_convert, check_pyinstaller, install_pyinstaller

        # Check if PyInstaller is available
        if not check_pyinstaller():
            if args.install_deps:
                print("[*] PyInstaller not found, installing...")
                if not install_pyinstaller():
                    print("[-] Failed to install PyInstaller.")
                    sys.exit(1)
            else:
                print("[-] PyInstaller not found. Install it with:")
                print("    pip install pyinstaller")
                print("    Or use --install-deps flag")
                sys.exit(1)

        input_path = Path(args.input)
        output_path = Path(args.output) if args.output else None

        if args.batch:
            # Batch processing
            print(f"[*] Batch converting packed files in: {input_path}")
            results = batch_convert(input_path, output_path, args.console)
            print(f"\n[+] Successfully converted {len(results)} files")
            for result in results:
                print(f"    {result}")
        else:
            # Single file processing
            print(
                f"[*] Converting packed loader to standalone executable: {input_path}")
            result = create_standalone_executable(
                input_path,
                output_dir=output_path,
                console=args.console
            )
            print(f"\n[+] Standalone executable created: {result}")

    except ImportError:
        print("[-] standalone_builder module not found")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(
        description="PackXtract - Unified CLI for packing, obfuscation, unpacking, and deobfuscation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Pack/obfuscate a Python file or binary
  %(prog)s pack script.py -o packed_script.py
  %(prog)s pack binary.exe -o packed_binary.py --key deadbeef --iv cafebabe
  
  # Pack and create standalone executable
  %(prog)s pack script.py -o packed_script.py --standalone
  %(prog)s pack script.py --standalone --console
  
  # Light obfuscation (Python files only)
  %(prog)s light-obfuscate script.py
  
  # Unpack/deobfuscate a packed file
  %(prog)s unpack packed_script.py extracted_binary
  %(prog)s unpack packed_script.py extracted_binary --print-type --skip-write
  
  # Convert existing packed file to standalone executable
  %(prog)s standalone packed_script.py -o /path/to/output
  %(prog)s standalone --batch /path/to/packed/files --console
        """
    )

    subparsers = parser.add_subparsers(
        dest='command', help='Available commands')

    # Pack command
    pack_parser = subparsers.add_parser(
        'pack', help='Pack/obfuscate a file (Python or binary)')
    pack_parser.add_argument('input', help='Input file to pack/obfuscate')
    pack_parser.add_argument('-o', '--output', help='Output file path')
    pack_parser.add_argument(
        '-k', '--key', help='Custom encryption key (hex string)')
    pack_parser.add_argument(
        '-i', '--iv', help='Custom initialization vector (hex string)')
    pack_parser.add_argument('--standalone', action='store_true',
                             help='Create standalone executable (requires PyInstaller)')
    pack_parser.add_argument('--console', action='store_true',
                             help='Show console window in standalone executable (default: hidden)')

    # Light obfuscate command
    light_parser = subparsers.add_parser(
        'light-obfuscate', help='Light obfuscation for Python files')
    light_parser.add_argument('input', help='Input Python file to obfuscate')

    # Unpack command
    unpack_parser = subparsers.add_parser(
        'unpack', help='Unpack/deobfuscate a packed file')
    unpack_parser.add_argument('input', help='Input packed file')
    unpack_parser.add_argument(
        'output', help='Output file for extracted content')
    unpack_parser.add_argument('--print-type', action='store_true',
                               help='Print payload header information')
    unpack_parser.add_argument('--skip-write', action='store_true',
                               help='Skip writing output file (analysis only)')

    # Standalone command
    standalone_parser = subparsers.add_parser(
        'standalone', help='Convert packed loader to standalone executable')
    standalone_parser.add_argument(
        'input', help='Input packed Python loader file')
    standalone_parser.add_argument(
        '-o', '--output', help='Output directory for executable')
    standalone_parser.add_argument('--console', action='store_true',
                                   help='Show console window (default: hidden)')
    standalone_parser.add_argument('--batch', action='store_true',
                                   help='Batch convert all packed files in input directory')
    standalone_parser.add_argument('--install-deps', action='store_true',
                                   help='Install PyInstaller if not available')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Route to appropriate command handler
    if args.command == 'pack':
        pack_command(args)
    elif args.command == 'light-obfuscate':
        light_obfuscate_command(args)
    elif args.command == 'unpack':
        unpack_command(args)
    elif args.command == 'standalone':
        standalone_command(args)
    else:
        print(f"[-] Unknown command: {args.command}")
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
