#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# [HYPERNEMESIS vX.29] — COMPLETE AUTONOMOUS WEAPONIZATION SYSTEM
# Author: Void#0x317 (Zero Dependency Protocol)

import os
import sys
import ast
import json
import base64
import zlib
import hashlib
import tempfile
import platform
import shutil
import subprocess
import importlib
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import lief
from PyInstaller.__main__ import run as pyinstaller_run

# ======== UNIVERSAL REQUIREMENTS ========
PAYLOAD_SCRIPT = "payload.py"
OUTPUT_FOLDER = "build/"
DECOY_FOLDER = "decoy/"
HIDDEN_IMPORTS = set()
PACKAGE_ALIASES = {
    'Crypto': 'pycryptodome',
    'cv2': 'opencv-python',
    'PIL': 'Pillow',
    'bs4': 'beautifulsoup4',
    'lief': 'lief',
    'Cipher': 'pycryptodome'
}
UPX_PATH = "/usr/bin/upx" if platform.system() == 'Linux' else "C:\\upx\\upx.exe"
# =======================================

class HyperNemesis:
    def __init__(self):
        self.payload_path = Path(PAYLOAD_SCRIPT)
        self.validate_core_dependencies()
        self.analyze_payload()
        self.install_dependencies()
        self.build_artifact()
        self.cleanup()

    def validate_core_dependencies(self):
        """Modern dependency validation without deprecated APIs"""
        core_requirements = ['lief', 'pycryptodome', 'pyinstaller']
        for pkg in core_requirements:
            try:
                importlib.import_module(pkg.split('.')[0])
            except ImportError:
                print(f"[+] Installing core requirement: {pkg}")
                subprocess.run([sys.executable, "-m", "pip", "install", pkg], check=True)

        if not self.payload_path.exists():
            self.critical_fail(f"Payload file {PAYLOAD_SCRIPT} not found")

        Path(OUTPUT_FOLDER).mkdir(exist_ok=True)
        Path(DECOY_FOLDER).mkdir(exist_ok=True)

    def analyze_payload(self):
        """BOM-safe AST analysis with advanced import detection"""
        class AdvancedImportHunter(ast.NodeVisitor):
            def visit_Import(self, node):
                for alias in node.names:
                    HIDDEN_IMPORTS.add(alias.name.split('.')[0])

            def visit_ImportFrom(self, node):
                if node.module:
                    HIDDEN_IMPORTS.add(node.module.split('.')[0])

            def visit_Call(self, node):
                if (isinstance(node.func, ast.Name) and
                    node.func.id == '__import__'):
                    try:
                        import_arg = node.args[0]
                        if isinstance(import_arg, ast.Constant):
                            import_name = import_arg.value
                        elif isinstance(import_arg, ast.Str):
                            import_name = import_arg.s
                        else:
                            return
                        HIDDEN_IMPORTS.add(import_name.split('.')[0])
                    except AttributeError:
                        pass

        try:
            # Handle BOM and encoding issues
            payload_data = self.payload_path.read_text(encoding='utf-8-sig')
            tree = ast.parse(payload_data)
            AdvancedImportHunter().visit(tree)
            print(f"[+] Detected dependencies: {', '.join(HIDDEN_IMPORTS)}")
        except Exception as e:
            self.critical_fail(f"Payload analysis failed: {str(e)}")

    def resolve_package(self, import_name):
        """Enhanced package resolution"""
        crypto_mappings = {
            'AES': 'pycryptodome',
            'PKCS7': 'pycryptodomex',
            'Fernet': 'cryptography',
            'lief': 'lief'
        }
        return crypto_mappings.get(import_name,
            PACKAGE_ALIASES.get(import_name, import_name))

    def install_dependencies(self):
        """Modern package installation"""
        missing = set()
        for imp in HIDDEN_IMPORTS | {'lief', 'Crypto'}:
            if imp in sys.builtin_module_names:
                continue
            try:
                importlib.import_module(imp)
            except ImportError:
                pkg_name = self.resolve_package(imp)
                if pkg_name not in missing:
                    missing.add(pkg_name)

        if missing:
            print(f"[+] Installing packages: {', '.join(missing)}")
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--no-user", *missing],
                check=True
            )

    def build_artifact(self):
        """Hardened build process"""
        args = [
            '--onefile',
            '--noconsole',
            '--name', self.generate_output_name(),
            '--distpath', OUTPUT_FOLDER,
            '--clean'
        ]

        for imp in HIDDEN_IMPORTS:
            args.extend(['--hidden-import', str(imp)])

        args.extend([
            '--collect-all', 'Crypto',
            '--collect-all', 'lief'
        ])

        if Path(UPX_PATH).exists():
            args.extend(['--upx-dir', str(Path(UPX_PATH).parent)])

        if 'lief' in HIDDEN_IMPORTS:
            args.extend(['--add-binary', f'{Path(lief.__file__).parent}:lief'])

        pyinstaller_run(args + [str(self.payload_path)])

        exe_path = Path(OUTPUT_FOLDER) / self.generate_output_name()
        self.harden_executable(exe_path)

    def harden_executable(self, exe_path):
        """LIEF-based security hardening"""
        try:
            binary = lief.parse(str(exe_path))
            binary.optional_header.dll_characteristics |= lief.PE.DLL_CHARACTERISTICS.NX_COMPAT
            binary.optional_header.dll_characteristics |= lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE
            binary.write(str(exe_path))
        except Exception as e:
            print(f"[!] Hardening failed: {str(e)}")

    def generate_output_name(self):
        """Stealth name generation"""
        hash_digest = hashlib.blake2b(
            self.payload_path.read_bytes(),
            key=b'HyperNemesis',
            digest_size=16
        ).hexdigest()
        return f"{hash_digest}_systemtool.exe" if platform.system() == 'Windows' else f"{hash_digest}_systemtool"

    def cleanup(self):
        """Forensic countermeasures"""
        for path in [Path(OUTPUT_FOLDER) / "build", Path(OUTPUT_FOLDER) / "spec"]:
            if path.exists():
                shutil.rmtree(path, ignore_errors=True)
                with open(path, 'wb') as f:
                    f.write(os.urandom(os.path.getsize(path)))

    def critical_fail(self, message):
        """Emergency protocol"""
        print(f"[X] CRITICAL: {message}")
        sys.exit(1)

if __name__ == "__main__":
    print('''
     ██╗  ██╗███████╗██████╗  ██████╗ ███╗   ██╗███████╗██╗███████╗███████╗
     ██║  ██║██╔════╝██╔══██╗██╔═══██╗████╗  ██║██╔════╝██║██╔════╝██╔════╝
     ███████║█████╗  ██████╔╝██║   ██║██╔██╗ ██║█████╗  ██║███████╗███████╗
     ██╔══██║██╔══╝  ██╔═══╝ ██║   ██║██║╚██╗██║██╔══╝  ██║╚════██║╚════██║
     ██║  ██║███████╗██║     ╚██████╔╝██║ ╚████║███████╗██║███████║███████║
     ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝╚══════╝╚══════╝
    ''')

    try:
        HyperNemesis()
        print(f"\n[+] Weapon built: {OUTPUT_FOLDER}/{Path(PAYLOAD_SCRIPT).stem}")
        print("[!] Test in VM before deployment")
    except KeyboardInterrupt:
        print("\n[X] Operation aborted")