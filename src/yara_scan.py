import os
import sys
import yara

def compile_rules(rules_path):
    try:
        if os.path.isfile(rules_path):
            return yara.compile(filepath=rules_path)
        elif os.path.isdir(rules_path):
            rule_files = {
                os.path.splitext(os.path.basename(f))[0]: os.path.join(rules_path, f)
                for f in os.listdir(rules_path)
                if f.endswith(('.yar', '.yara'))
            }
            if not rule_files:
                raise ValueError("No .yar or .yara files found in directory.")
            return yara.compile(filepaths=rule_files)
        else:
            raise ValueError("Rules path is neither a file nor a directory.")
    except yara.SyntaxError as e:
        print(f"YARA Syntax Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error compiling rules: {e}")
        sys.exit(1)

def scan_file(filepath, rules):
    try:
        matches = rules.match(filepath)
        if matches:
            print(f"Match in {filepath}:")
            for match in matches:
                print(f"    Rule: {match.rule}")
                if match.meta:
                    for k, v in match.meta.items():
                        #print(f"      Meta: {k} = {v}")
                        pass
                if match.strings:
                    for string_match in match.strings:
                        identifier = string_match.identifier
                        for instance in string_match.instances:
                            offset = instance.offset
                            data = instance.matched_data
                            try:
                                printable_data = data.decode('utf-8', errors='replace')
                            except Exception:
                                printable_data = repr(data)
                            print(f"      String ({identifier}) at 0x{offset:08x}: {printable_data}")
    except yara.Error as e:
        print(f"YARA error scanning {filepath}: {e}")
    except PermissionError:
        print(f"Permission denied: {filepath}")
    except Exception as e:
        print(f"Unexpected error scanning {filepath}: {e}")

def scan_directory(root_path, rules):
    for dirpath, _, filenames in os.walk(root_path):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            # Пропускаем файлы без чтения (например, слишком большие или специальные)
            if os.path.isfile(filepath):
                scan_file(filepath, rules)

def main():
    if len(sys.argv) != 3:
        print("Usage: python yara_scan.py <rules.yar|rules_dir> <target_dir_or_file>")
        sys.exit(1)

    rules_arg = sys.argv[1]
    target = sys.argv[2]

    print(f"Compiling YARA rules from: {rules_arg}")
    rules = compile_rules(rules_arg)

    if os.path.isfile(target):
        print(f"Scanning single file: {target}")
        scan_file(target, rules)
    elif os.path.isdir(target):
        print(f"Recursively scanning directory: {target}")
        scan_directory(target, rules)
    else:
        print(f"Target not found: {target}")
        sys.exit(1)

    print("Scan completed.")

if __name__ == "__main__":
    main()