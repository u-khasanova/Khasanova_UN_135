import sys
import os

MAGIC = {
    b'MZ': 'Windows PE executable (EXE/DLL)',
    b'\x7fELF': 'ELF executable (Linux/Unix)',
    b'\x4d\x5a': 'Windows PE file (alternative MZ)',
    b'PK\x03\x04': 'ZIP archive (or DOCX, XLSX, etc.)',
    b'PK\x05\x06': 'ZIP64 archive',
    b'PK\x07\x08': 'ZIP spanned archive',
    b'\x50\x4b\x03\x04': 'ZIP-based Office document or JAR',
    b'\x25PDF': 'PDF document',
    b'\xff\xd8\xff': 'JPEG image',
    b'\x89PNG': 'PNG image',
    b'GIF87a': 'GIF image',
    b'GIF89a': 'GIF image',
    b'RIFF': 'RIFF container (AVI, WAV, WEBP)',
    b'BM': 'BMP image',
    b'7z\xbc\xaf\x27\x1c': '7z archive',
    b'\x1f\x8b': 'GZIP archive',
    b'BZh': 'BZIP2 archive',
    b'\xfd7zXZ\x00': 'XZ archive',
}

UPX_MAGIC = b'UPX!'

def detect_file_type(filepath):
    if not os.path.isfile(filepath):
        print(f"File not found: {filepath}")
        return

    with open(filepath, 'rb') as f:
        header = f.read(32)  


    if header.startswith(b'MZ'):
        print("Detected: Windows PE executable (EXE/DLL)")
        if UPX_MAGIC in header:
            print("UPX signature found")
        else:
            with open(filepath, 'rb') as f:
                data = f.read(1024)
                if UPX_MAGIC in data:
                    print("UPX signature found in first 1KB")
        return

    for magic, desc in MAGIC.items():
        if header.startswith(magic):
            print(f"Detected: {desc}")
            return

    print("Unknown file format. Possibly packed or obfuscated.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(1)
    detect_file_type(sys.argv[1])