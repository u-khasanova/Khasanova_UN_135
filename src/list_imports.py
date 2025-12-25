import pefile
import sys

def list_imports(filepath):
    try:
        pe = pefile.PE(filepath)
    except pefile.PEFormatError:
        print("Not a valid PE file.")
        return
    except Exception as e:
        print(f"Error: {e}")
        return

    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print("No imports found.")
        return

    print(f"Imports from: {filepath}\n")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('utf-8', errors='replace')
        print(f"    {dll_name}")
        for imp in entry.imports:
            func_name = None
            if imp.name:
                func_name = imp.name.decode('utf-8', errors='replace')
            elif imp.ordinal:
                func_name = f"ORDINAL:{imp.ordinal}"
            else:
                func_name = "UNKNOWN"
            print(f"    {func_name}")
        print()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python list_imports.py <file.exe>")
        sys.exit(1)
    list_imports(sys.argv[1])