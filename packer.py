from Crypto.Util.Padding import unpad
import ast
import base64
import hashlib
import marshal
import os
import random
import sys
import traceback
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class UltimateObfuscator:
    def __init__(self, filename):
        self.filename = filename
        self.aes_key = os.urandom(32)
        self.iv = os.urandom(16)
        if filename is not None:
            self.is_python = self.filename.endswith('.py')
            if self.is_python:
                self.code = self._read_file_text()
            else:
                self.code = self._read_file_binary()
        else:
            self.is_python = None
            self.code = None

    def _read_file_text(self):
        with open(self.filename, 'r', encoding='utf-8') as f:
            return f.read()

    def _read_file_binary(self):
        with open(self.filename, 'rb') as f:
            return f.read()

    class VariableCollector(ast.NodeVisitor):
        def __init__(self):
            self.assigned_vars = set()

        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Store):
                self.assigned_vars.add(node.id)
            self.generic_visit(node)

        def visit_arg(self, node):
            self.assigned_vars.add(node.arg)
            self.generic_visit(node)

    def print_help(self):
        print("""
PackXtract - Advanced Python and Executable Obfuscator/Packer

Usage:
  python packer.py <file.py|file.exe|file.bin|...> [options]

Options:
  -h, --help          Show this help message and exit
  -o, --output <path> Specify the output file path
  -k, --key <key>     Specify a custom AES key (32 bytes)
  -i, --iv <iv>       Specify a custom IV (16 bytes)

Description:
  Obfuscate Python scripts or pack executables/binaries with AES encryption, AST transformations, and anti-debugging features.
  Output is written to 'obfuscated.py' (for Python) or 'packed_executable_loader.py' (for binaries) by default.

Examples:
  python packer.py myscript.py
  python packer.py myscript.py -o custom_output.py
  python packer.py myscript.py -k customkey -i customiv
""")

    class VariableRenamer(ast.NodeTransformer):
        def __init__(self, assigned_vars):
            self.var_map = {}
            self.assigned_vars = assigned_vars

        def _obf_name(self, original):
            return f"var_{hashlib.shake_128(original.encode()).hexdigest(8)}"

        def visit_Name(self, node):
            if node.id in self.assigned_vars:
                if node.id not in self.var_map:
                    self.var_map[node.id] = self._obf_name(node.id)
                node.id = self.var_map[node.id]
            return node

        def visit_arg(self, node):
            if node.arg in self.assigned_vars:
                if node.arg not in self.var_map:
                    self.var_map[node.arg] = self._obf_name(node.arg)
                node.arg = self.var_map[node.arg]
            return node

    class ControlFlowFlattener(ast.NodeTransformer):
        def visit_FunctionDef(self, node):
            self.generic_visit(node)
            state_var = f"state_{random.randint(1000, 9999)}"
            new_body = [
                ast.Assign(
                    targets=[ast.Name(id=state_var, ctx=ast.Store())],
                    value=ast.Constant(value=0)
                )
            ]
            while_body = []
            for i, stmt in enumerate(node.body):
                while_body.append(
                    ast.If(
                        test=ast.Compare(
                            left=ast.Name(id=state_var, ctx=ast.Load()),
                            ops=[ast.Eq()],
                            comparators=[ast.Constant(value=i)]
                        ),
                        body=[
                            stmt,
                            ast.AugAssign(
                                target=ast.Name(id=state_var, ctx=ast.Store()),
                                op=ast.Add(),
                                value=ast.Constant(value=1)
                            )
                        ],
                        orelse=[]
                    )
                )
            new_body.append(
                ast.While(
                    test=ast.Compare(
                        left=ast.Name(id=state_var, ctx=ast.Load()),
                        ops=[ast.Lt()],
                        comparators=[ast.Constant(value=len(node.body))]
                    ),
                    body=while_body,
                    orelse=[]
                )  # type: ignore
            )
            node.body = new_body  # type: ignore[list-assign]
            return node

    class StringEncryptor(ast.NodeTransformer):
        def __init__(self, obfuscator):
            self.obfuscator = obfuscator
            self.in_fstring = False

        def visit_JoinedStr(self, node):
            self.in_fstring = True
            self.generic_visit(node)
            self.in_fstring = False
            return node

        def visit_Constant(self, node):
            if isinstance(node.value, str) and not self.in_fstring:
                cipher = AES.new(self.obfuscator.aes_key,
                                 AES.MODE_CBC, self.obfuscator.iv)
                encrypted = cipher.encrypt(pad(node.value.encode(), 16))
                return ast.Call(
                    func=ast.Name(id='_decrypt_str', ctx=ast.Load()),
                    args=[ast.Constant(value=encrypted)],
                    keywords=[]
                )
            return node

    def _transform_ast(self):
        if not isinstance(self.code, str):
            raise ValueError("Code must be a string to parse with ast.parse")
        tree = ast.parse(self.code)

        # Collect variables to rename
        collector = self.VariableCollector()
        collector.visit(tree)
        assigned_vars = collector.assigned_vars

        transformers = [
            self.VariableRenamer(assigned_vars),
            self.ControlFlowFlattener(),
            self.StringEncryptor(self),
        ]

        for transformer in transformers:
            tree = transformer.visit(tree)
            ast.fix_missing_locations(tree)

        return marshal.dumps(compile(tree, "<obfuscated>", "exec"))

    def _build_loader(self, encrypted_data):
        return f"""
import sys
import os
import base64
import hashlib
import marshal
import zlib
import traceback
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def _anti_debug():
    if sys.gettrace() or (os.name == 'nt' and __import__('ctypes').windll.kernel32.IsDebuggerPresent()):
        sys.exit(1)
_anti_debug()

_KEY = {self.aes_key!r}
_IV = {self.iv!r}

def _decrypt_str(data):
    try:
        cipher = AES.new(_KEY, AES.MODE_CBC, _IV)
        return unpad(cipher.decrypt(data), 16).decode()
    except:
        return ""

def _main():
    try:
        _encrypted = {encrypted_data!r}
        cipher = AES.new(_KEY, AES.MODE_CBC, _IV)
        encrypted_data = base64.b85decode(_encrypted)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), 16)
        decompressed_data = zlib.decompress(decrypted_data)
        exec(marshal.loads(decompressed_data), {{
            **globals(),
            '__name__': '__main__',
            '__builtins__': __builtins__,
            '_decrypt_str': _decrypt_str
        }})
    except Exception as e:
        print("Execution failed:")
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    _main()
"""

    def _build_exe_loader(self, encrypted_data, original_name):
        return f'''\
import sys
import os
import base64
import zlib
import tempfile
import subprocess
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def _anti_debug():
    if sys.gettrace() or (os.name == 'nt' and hasattr(__import__('ctypes'), 'windll') and __import__('ctypes').windll.kernel32.IsDebuggerPresent()):
        sys.exit(1)
_anti_debug()

_KEY = {repr(self.aes_key)}
_IV = {repr(self.iv)}

def _main():
    try:
        _encrypted = {repr(encrypted_data)}
        cipher = AES.new(_KEY, AES.MODE_CBC, _IV)
        encrypted_data = base64.b85decode(_encrypted)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), 16)
        decompressed_data = zlib.decompress(decrypted_data)
        # Write to temp file
        suffix = os.path.splitext({repr(original_name)})[-1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(decompressed_data)
            tmp.flush()
            tmp_path = tmp.name
        # Make executable (Linux/Mac)
        if os.name != 'nt':
            os.chmod(tmp_path, 0o755)
        # Execute
        try:
            if os.name == 'nt':
                subprocess.run([tmp_path], check=True)
            else:
                subprocess.run([tmp_path], check=True)
        finally:
            os.remove(tmp_path)
    except Exception as e:
        print("Execution failed:", e)
        sys.exit(1)

if __name__ == '__main__':
    _main()
'''

    def obfuscate(self, output_path=None, custom_key=None, custom_iv=None):
        if custom_key:
            self.aes_key = base64.b64decode(custom_key)
        if custom_iv:
            self.iv = base64.b64decode(custom_iv)

        if self.is_python:
            transformed = self._transform_ast()
            compressed = zlib.compress(transformed, level=9)
            cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
            encrypted = base64.b85encode(
                cipher.encrypt(pad(compressed, 16))).decode()
            out_path = output_path if output_path else os.path.abspath(
                "output/obfuscated.py")
            with open(out_path, "w") as f:
                f.write(self._build_loader(encrypted))
            print(f"[SUCCESS] Python file obfuscated.")
            print(f"  Output: {out_path}")
            print(f"  AES Key: {self.aes_key.hex()}")
            print(f"  IV: {self.iv.hex()}")
        else:
            if isinstance(self.code, bytes):
                code_bytes = self.code
            elif isinstance(self.code, str):
                code_bytes = self.code.encode('utf-8')
            else:
                if self.code is None:
                    raise ValueError(
                        "No code to obfuscate (self.code is None)")
                code_bytes = bytes(self.code)
            compressed = zlib.compress(code_bytes, level=9)
            cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
            encrypted = base64.b85encode(
                cipher.encrypt(pad(compressed, 16))).decode()
            out_path = output_path if output_path else os.path.abspath(
                "output/packed_executable_loader.py")
            with open(out_path, "w") as f:
                f.write(self._build_exe_loader(
                    encrypted, os.path.basename(self.filename)))
            print(f"[SUCCESS] Executable packed.")
            print(f"  Output: {out_path}")
            print(f"  AES Key: {self.aes_key.hex()}")
            print(f"  IV: {self.iv.hex()}")
            print(f"  To run: python {out_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        UltimateObfuscator(None).print_help()
        sys.exit(0)

    output_path = None
    custom_key = None
    custom_iv = None

    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ('-o', '--output'):
            output_path = sys.argv[i + 1]
            i += 2
        elif arg in ('-k', '--key'):
            custom_key = sys.argv[i + 1]
            i += 2
        elif arg in ('-i', '--iv'):
            custom_iv = sys.argv[i + 1]
            i += 2
        else:
            filename = arg
            i += 1

    if 'filename' not in locals():
        print("Error: No filename provided.")
        UltimateObfuscator(None).print_help()
        sys.exit(1)

    UltimateObfuscator(filename).obfuscate(output_path, custom_key, custom_iv)
