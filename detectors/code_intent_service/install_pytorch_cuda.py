"""
PyTorch CUDA Installation Script
=================================

Installiert PyTorch mit CUDA-Unterstützung für RTX 3080Ti.

Usage:
    python install_pytorch_cuda.py
    python install_pytorch_cuda.py --cuda 12.1
    python install_pytorch_cuda.py --cuda 11.8
"""

import subprocess
import sys
import argparse


def check_cuda_version():
    """Prüft CUDA-Version via nvidia-smi."""
    try:
        result = subprocess.run(
            ['nvidia-smi'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            # Parse CUDA version from nvidia-smi output
            for line in result.stdout.split('\n'):
                if 'CUDA Version:' in line:
                    cuda_version = line.split('CUDA Version:')[1].strip().split()[0]
                    return cuda_version
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass
    return None


def uninstall_pytorch():
    """Deinstalliert aktuelle PyTorch-Installation."""
    print("=" * 60)
    print("Schritt 1: Deinstalliere aktuelle PyTorch-Version...")
    print("=" * 60)
    
    packages = ['torch', 'torchvision', 'torchaudio']
    for package in packages:
        try:
            subprocess.run(
                [sys.executable, '-m', 'pip', 'uninstall', package, '-y'],
                check=False
            )
        except Exception as e:
            print(f"Warnung: Fehler beim Deinstallieren von {package}: {e}")
    
    print("✓ PyTorch deinstalliert\n")


def install_pytorch_cuda(cuda_version='12.1'):
    """Installiert PyTorch mit CUDA-Unterstützung."""
    print("=" * 60)
    print(f"Schritt 2: Installiere PyTorch mit CUDA {cuda_version}...")
    print("=" * 60)
    
    if cuda_version == '12.1':
        index_url = 'https://download.pytorch.org/whl/cu121'
    elif cuda_version == '11.8':
        index_url = 'https://download.pytorch.org/whl/cu118'
    else:
        print(f"Fehler: Unbekannte CUDA-Version: {cuda_version}")
        print("Unterstützte Versionen: 12.1, 11.8")
        return False
    
    try:
        subprocess.run(
            [
                sys.executable, '-m', 'pip', 'install',
                'torch', 'torchvision', 'torchaudio',
                '--index-url', index_url
            ],
            check=True
        )
        print(f"✓ PyTorch mit CUDA {cuda_version} installiert\n")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Fehler bei der Installation: {e}")
        return False


def verify_installation():
    """Verifiziert PyTorch CUDA-Installation."""
    print("=" * 60)
    print("Schritt 3: Verifiziere Installation...")
    print("=" * 60)
    
    try:
        import torch
        
        print(f"PyTorch Version: {torch.__version__}")
        
        if '+cpu' in torch.__version__:
            print("✗ FEHLER: PyTorch wurde immer noch als CPU-Version installiert!")
            print("  Bitte manuell installieren:")
            print("  pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121")
            return False
        
        cuda_available = torch.cuda.is_available()
        print(f"CUDA verfügbar: {cuda_available}")
        
        if cuda_available:
            print(f"CUDA Version: {torch.version.cuda}")
            print(f"GPU: {torch.cuda.get_device_name(0)}")
            print(f"GPU Memory: {torch.cuda.get_device_properties(0).total_memory / (1024**3):.1f} GB")
            print("✓ PyTorch CUDA-Installation erfolgreich!")
            return True
        else:
            print("✗ CUDA ist nicht verfügbar")
            print("  Mögliche Ursachen:")
            print("  - NVIDIA-Treiber nicht installiert")
            print("  - CUDA Toolkit nicht installiert")
            print("  - PyTorch-Version passt nicht zur CUDA-Version")
            return False
            
    except ImportError:
        print("✗ PyTorch konnte nicht importiert werden")
        return False
    except Exception as e:
        print(f"✗ Fehler bei der Verifizierung: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Installiert PyTorch mit CUDA-Unterstützung'
    )
    parser.add_argument(
        '--cuda',
        type=str,
        default='auto',
        choices=['auto', '12.1', '11.8'],
        help='CUDA-Version (auto = automatisch erkennen)'
    )
    
    args = parser.parse_args()
    
    # CUDA-Version bestimmen
    if args.cuda == 'auto':
        detected_cuda = check_cuda_version()
        if detected_cuda:
            print(f"Erkannte CUDA-Version: {detected_cuda}")
            # Map detected version to supported version
            if detected_cuda.startswith('12'):
                cuda_version = '12.1'
            elif detected_cuda.startswith('11'):
                cuda_version = '11.8'
            else:
                print(f"Warnung: Unbekannte CUDA-Version {detected_cuda}, verwende 12.1")
                cuda_version = '12.1'
        else:
            print("CUDA-Version konnte nicht erkannt werden, verwende 12.1 (Standard)")
            cuda_version = '12.1'
    else:
        cuda_version = args.cuda
    
    print("\n" + "=" * 60)
    print("PyTorch CUDA Installation")
    print("=" * 60)
    print(f"Ziel: PyTorch mit CUDA {cuda_version} installieren")
    print("=" * 60 + "\n")
    
    # Schritt 1: Deinstallieren
    uninstall_pytorch()
    
    # Schritt 2: Installieren
    if not install_pytorch_cuda(cuda_version):
        print("✗ Installation fehlgeschlagen")
        sys.exit(1)
    
    # Schritt 3: Verifizieren
    if not verify_installation():
        print("\n✗ Verifizierung fehlgeschlagen")
        print("\nBitte manuell prüfen:")
        print("  python -c \"import torch; print(torch.cuda.is_available())\"")
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print("✓ Installation erfolgreich abgeschlossen!")
    print("=" * 60)
    print("\nBitte den Service neu starten:")
    print("  cd detectors/code_intent_service")
    print("  python -m uvicorn api.main:app --reload --port 8000")


if __name__ == '__main__':
    main()

