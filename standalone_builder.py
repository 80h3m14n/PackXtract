#!/usr/bin/env python3
"""
Standalone Builder - Convert packed Python loaders to standalone executables.

This script takes packed .py loader files and converts them to standalone
executables that don't require Python to be installed on the target system.
"""

import os
import sys
import subprocess
import tempfile
import shutil
from pathlib import Path
import argparse


def check_pyinstaller():
    """Check if PyInstaller is available."""
    try:
        subprocess.run(['pyinstaller', '--version'],
                       capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def install_pyinstaller():
    """Install PyInstaller if not available."""
    print("[*] PyInstaller not found. Installing...")
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'pyinstaller>=5.0.0'],
                       check=True)
        print("[+] PyInstaller installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to install PyInstaller: {e}")
        return False


from typing import Optional

def create_standalone_executable(input_file: Path, output_dir: Optional[Path] = None,
                                 console: bool = False, icon: Optional[Path] = None) -> Path:
    """
    Convert a packed Python loader to a standalone executable.

    Args:
        input_file: Path to the packed .py loader file
        output_dir: Directory to place the executable (default: same as input)
        console: If True, show console window (default: False for GUI mode)
        icon: Optional icon file for the executable

    Returns:
        Path to the created executable
    """
    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_file}")

    if not input_file.suffix == '.py':
        raise ValueError("Input file must be a Python (.py) file")

    # Set default output directory
    if output_dir is None:
        output_dir = input_file.parent / "standalone"

    output_dir.mkdir(exist_ok=True)

    # Prepare PyInstaller command
    cmd = [
        'pyinstaller',
        '--onefile',  # Create single executable file
        '--distpath', str(output_dir),  # Output directory
        '--workpath', str(output_dir / 'build'),  # Build directory
        '--specpath', str(output_dir / 'spec'),  # Spec file directory
        '--clean',  # Clean before building
    ]

    # Console mode
    if not console:
        cmd.append('--noconsole')  # No console window (for GUI apps)

    # Icon
    if icon and icon.exists():
        cmd.extend(['--icon', str(icon)])

    # Add hidden imports for our dependencies
    cmd.extend([
        '--hidden-import', 'Crypto.Cipher.AES',
        '--hidden-import', 'Crypto.Util.Padding',
        '--hidden-import', 'base64',
        '--hidden-import', 'zlib',
        '--hidden-import', 'marshal',
    ])

    # Input file
    cmd.append(str(input_file))

    print(f"[*] Building standalone executable from {input_file.name}")
    print(f"[*] Command: {' '.join(cmd)}")

    try:
        # Run PyInstaller
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True)

        # Find the created executable
        executable_name = input_file.stem
        if os.name == 'nt':
            executable_name += '.exe'

        executable_path = output_dir / executable_name

        if executable_path.exists():
            file_size = executable_path.stat().st_size / (1024 * 1024)  # MB
            print(f"[+] Standalone executable created: {executable_path}")
            print(f"[+] Size: {file_size:.1f} MB")

            # Clean up build artifacts
            build_dir = output_dir / 'build'
            spec_dir = output_dir / 'spec'
            if build_dir.exists():
                shutil.rmtree(build_dir)
            if spec_dir.exists():
                shutil.rmtree(spec_dir)

            return executable_path
        else:
            raise RuntimeError("Executable was not created")

    except subprocess.CalledProcessError as e:
        print(f"[-] PyInstaller failed:")
        print(f"    stdout: {e.stdout}")
        print(f"    stderr: {e.stderr}")
        raise


def batch_convert(input_dir: Path, output_dir: Optional[Path] = None, console: bool = False):
    """Convert all packed .py files in a directory to standalone executables."""
    if not input_dir.exists():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")

    # Find all .py files that look like packed loaders
    py_files = list(input_dir.glob("*.py"))
    loader_files = []

    for py_file in py_files:
        # Check if it looks like a packed loader (contains _KEY, _IV, _encrypted)
        try:
            content = py_file.read_text(errors='ignore')
            if '_KEY' in content and '_IV' in content and ('_encrypted' in content or 'marshal.loads' in content):
                loader_files.append(py_file)
        except Exception:
            continue

    if not loader_files:
        print(f"[-] No packed loader files found in {input_dir}")
        return []

    print(f"[*] Found {len(loader_files)} packed loader files")

    results = []
    for loader_file in loader_files:
        try:
            executable_path = create_standalone_executable(
                loader_file,
                output_dir=output_dir or input_dir / "standalone",
                console=console
            )
            results.append(executable_path)
        except Exception as e:
            print(f"[-] Failed to convert {loader_file.name}: {e}")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Convert packed Python loaders to standalone executables",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Convert single packed loader
  %(prog)s packed_loader.py
  
  # Convert with custom output directory
  %(prog)s packed_loader.py -o /path/to/output
  
  # Convert with console window visible
  %(prog)s packed_loader.py --console
  
  # Batch convert all loaders in directory
  %(prog)s --batch /path/to/packed/files
  
  # Convert with custom icon
  %(prog)s packed_loader.py --icon app.ico
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('input_file', nargs='?', type=Path,
                       help='Input packed Python loader file')
    group.add_argument('--batch', type=Path,
                       help='Batch convert all packed files in directory')

    parser.add_argument('-o', '--output', type=Path,
                        help='Output directory (default: same as input)')
    parser.add_argument('--console', action='store_true',
                        help='Show console window (default: hidden)')
    parser.add_argument('--icon', type=Path,
                        help='Icon file for the executable (.ico on Windows)')
    parser.add_argument('--install-deps', action='store_true',
                        help='Install PyInstaller if not available')

    args = parser.parse_args()

    # Check PyInstaller availability
    if not check_pyinstaller():
        if args.install_deps:
            if not install_pyinstaller():
                sys.exit(1)
        else:
            print("[-] PyInstaller not found. Install it with:")
            print("    pip install pyinstaller")
            print("    Or use --install-deps flag")
            sys.exit(1)

    try:
        if args.batch:
            # Batch processing
            results = batch_convert(args.batch, args.output, args.console)
            print(f"\n[+] Successfully converted {len(results)} files")
            for result in results:
                print(f"    {result}")
        else:
            # Single file processing
            result = create_standalone_executable(
                args.input_file,
                args.output,
                args.console,
                args.icon
            )
            print(f"\n[+] Conversion complete: {result}")

    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
