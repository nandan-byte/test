import os
import shutil
import ast
import base64
# pyrefly: ignore [missing-import]
import python_minifier

# Hardcoded XOR key for string encryption
XOR_KEY = 42

class SecurityASTTransformer(ast.NodeTransformer):
    def __init__(self):
        self.joined_str_depth = 0

    def visit_JoinedStr(self, node):
        self.joined_str_depth += 1
        self.generic_visit(node)
        self.joined_str_depth -= 1
        return node

    def visit_Constant(self, node):
        # Encrypt String Literals
        if isinstance(node.value, str):
            original_str = node.value
            # Don't encrypt docstrings, empty strings, or strings inside f-strings
            if not original_str or len(original_str) < 2 or self.joined_str_depth > 0:
                return node
            
            # Encode to utf-8 bytes first, then XOR and Base64 encode
            utf8_bytes = original_str.encode('utf-8')
            xored = bytes(b ^ XOR_KEY for b in utf8_bytes)
            b64 = base64.b64encode(xored).decode('utf-8')
            
            # Create AST node for: bytes(b ^ 42 for b in __import__('base64').b64decode("...")).decode('utf-8')
            decryption_code = f'bytes(b ^ {XOR_KEY} for b in __import__("base64").b64decode("{b64}")).decode("utf-8")'
            try:
                decrypted_node = ast.parse(decryption_code, mode='eval').body
                return ast.copy_location(decrypted_node, node)
            except Exception:
                return node
        return node

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        
        # Inject Opaque Predicate to flatten/scramble Control Flow (CFF)
        opaque_predicate = ast.parse(
            "if __import__('random').randint(0, 1) == 2: __import__('sys').exit(0)"
        ).body[0]
        
        # Insert at the beginning of the function
        if len(node.body) > 0:
            # Check if first node is a docstring
            if isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant):
                node.body.insert(1, opaque_predicate)
            else:
                node.body.insert(0, opaque_predicate)
        
        return node

def obfuscate_directory(src_dir, dest_dir):
    if os.path.exists(dest_dir):
        shutil.rmtree(dest_dir)
    shutil.copytree(src_dir, dest_dir)
    
    for root, _, files in os.walk(dest_dir):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                print(f"Obfuscating {filepath}...")
                with open(filepath, 'r', encoding='utf-8') as f:
                    source = f.read()
                
                try:
                    # 1. AST Mangling (String Encryption + CFG Scrambling)
                    tree = ast.parse(source)
                    transformer = SecurityASTTransformer()
                    tree = transformer.visit(tree)
                    ast.fix_missing_locations(tree)
                    mangled_source = ast.unparse(tree)
                    
                    # 2. Python Minifier (Hashing Locals/Constants)
                    obfuscated = python_minifier.minify(
                        mangled_source,
                        rename_locals=True,
                        rename_globals=False, # Protect dynamic imports
                        hoist_literals=True,
                        remove_annotations=True,
                        remove_pass=True,
                        remove_literal_statements=True
                    )
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(obfuscated)
                except Exception as e:
                    print(f"Failed to obfuscate {filepath}: {e}")

if __name__ == "__main__":
    src = os.path.abspath("appsecai")
    dest = os.path.abspath("build_staging/appsecai")
    
    print("[*] Starting Hyper-Aggressive AST Mangling...")
    obfuscate_directory(src, dest)
    print("[+] AST Mangling complete. Code ready in build_staging/appsecai")
