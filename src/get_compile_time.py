import pefile
import sys
import datetime

def get_compile_time(filepath):
    try:
        pe = pefile.PE(filepath)
        timestamp = pe.FILE_HEADER.TimeDateStamp
        compile_time = datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
        print(f"File: {filepath}")
        print(f"Compile Time (UTC): {compile_time}")
        print(f"Raw Timestamp: {timestamp}")
    except pefile.PEFormatError:
        print("Not a valid PE file.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python get_compile_time.py <file>")
        sys.exit(1)
    get_compile_time(sys.argv[1])