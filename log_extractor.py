#!/usr/bin/env python3
import os
import sys
import shutil
import tarfile
import argparse
import getpass

def parse_args():
    parser = argparse.ArgumentParser(
        description="Collect and extract case logs/cores into a destination directory."
    )
    parser.add_argument(
        "case_num",
        help="Case number in the format YYYY-XXXX (e.g. 2024-1234)"
    )
    parser.add_argument(
        "dest_root",
        help="Root folder where case data will be copied/extracted"
    )
    return parser.parse_args()

def ensure_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except Exception as e:
        print(f"\033[91mERROR: Cannot create directory {path}: {e}\033[0m")
        sys.exit(1)

def copy_file(src, dst):
    try:
        shutil.copy2(src, dst)
        print(f"  • Copied: {os.path.basename(src)}")
    except Exception as e:
        print(f"\033[91mERROR: Failed to copy {src} → {dst}: {e}\033[0m")

def extract_tgz(src, extract_to):
    try:
        with tarfile.open(src) as tf:
            tf.extractall(extract_to)
        print(f"  • Extracted: {os.path.basename(src)} → {extract_to}")
    except tarfile.ReadError:
        print(f"\033[91mERROR: {src} is not a valid tarfile\033[0m")
    except Exception as e:
        print(f"\033[91mERROR: Failed to extract {src}: {e}\033[0m")

def main():
    args = parse_args()

    user_name = getpass.getuser()
    print(f"\n\033[94mUser: {user_name}\033[0m")
    case_num = args.case_num.strip()
    print(f"\n\033[94mCase number: {case_num}\033[0m")

    # Build paths
    year = case_num.split('-', 1)[0]
    case_vol = f"/volume/case_{year}/{case_num}"
    print(f"\nChecking case volume directory: {case_vol}")
    if not os.path.isdir(case_vol):
        print(f"\033[91mERROR: Case volume {case_vol} does not exist.\033[0m")
        sys.exit(1)
    print("  ✓ Found case volume.")

    # Destination root must exist or be created
    dest_root = os.path.abspath(args.dest_root)
    print(f"\nPreparing destination root: {dest_root}")
    ensure_dir(dest_root)

    # Now per-case folder under dest_root
    csdata_dir = os.path.join(dest_root, case_num)
    print(f"Creating case folder: {csdata_dir}")
    ensure_dir(csdata_dir)

    # Process files
    print(f"\nProcessing files in {case_vol} ...\n")
    for fname in os.listdir(case_vol):
        src_path = os.path.join(case_vol, fname)

        # core-tarball or .core. files
        if "core-tarball" in fname or ".core." in fname:
            print(f"Core file detected: {fname}")
            copy_file(src_path, csdata_dir)

        # compressed logs
        elif fname.endswith(".tgz"):
            extract_path = os.path.join(csdata_dir, os.path.splitext(fname)[0])
            ensure_dir(extract_path)
            print(f"TGZ detected: {fname}")
            extract_tgz(src_path, extract_path)

        # everything else
        else:
            print(f"Copying other file: {fname}")
            copy_file(src_path, csdata_dir)

    # Final permissions
    try:
        print(f"\nSetting permissions (777) in {csdata_dir} ...")
        for root, dirs, files in os.walk(csdata_dir):
            os.chmod(root, 0o777)
            for f in files:
                os.chmod(os.path.join(root, f), 0o777)
        print("\033[92mAll files are now in:\033[0m", csdata_dir)
    except Exception as e:
        print(f"\033[91mWARNING: Could not set permissions: {e}\033[0m")

if __name__ == "__main__":
    main()
