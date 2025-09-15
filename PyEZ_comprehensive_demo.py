#!/usr/bin/env python3
"""
Comprehensive PyEZ Use Cases Demonstration

This script demonstrates key PyEZ functionalities:
  1. Device connectivity and facts retrieval.
  2. CLI command execution and raw RPC calls.
  3. Configuration management using the Config utility:
       - Locking, loading a merge candidate, diffing, and discarding.
  4. Software upgrade operations using the SW utility:
       - Retrieving the current software version.
       - (Examples for install, reboot, and rollback are provided as commented-out code.)
  5. File system operations using the FS utility (if available):
       - Listing filesystem details and examples for mkdir, copy, and delete operations.

Before running, update the device connection details (hostname, username, password).
"""

import sys
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.utils.sw import SW

try:
    from jnpr.junos.utils.fs import FS
except ImportError:
    FS = None

def demo_device_facts(device):
    print("\n=== Device Facts ===")
    facts = device.facts
    for key, value in facts.items():
        print(f"{key}: {value}")

def demo_cli_commands(device):
    print("\n=== CLI Command Execution ===")
    try:
        # Execute a simple CLI command (e.g., "show version").
        output = device.cli("show version", format="text")
        print("Output of 'show version':\n", output)
    except Exception as e:
        print("Error executing CLI command:", e)

def demo_rpc_operations(device):
    print("\n=== RPC Operations ===")
    try:
        # Retrieve the device configuration via RPC (returns an XML element).
        config_xml = device.rpc.get_configuration()
        print("Configuration retrieved via RPC:\n", config_xml)
    except Exception as e:
        print("Error performing RPC operation:", e)

def demo_config_operations(device):
    print("\n=== Configuration Management ===")
    cfg = Config(device)
    try:
        print("Locking configuration...")
        cfg.lock()

        # For demonstration, we use a candidate configuration snippet to change the hostname.
        candidate_config = """
system {
    host-name demo-pyez;
}
"""
        print("Loading candidate configuration as merge...")
        cfg.load(candidate_config, format="text", merge=True)

        print("Showing configuration diff:")
        diff = cfg.diff()
        print(diff)

        # Instead of committing, we discard the candidate configuration to avoid changes.
        print("Discarding candidate configuration...")
        cfg.discard()
        print("Candidate configuration discarded.")
    except Exception as e:
        print("Error during configuration operations:", e)
        try:
            cfg.discard()
        except Exception as discard_err:
            print("Error discarding candidate configuration:", discard_err)
    finally:
        try:
            cfg.unlock()
        except Exception as unlock_err:
            print("Error unlocking configuration:", unlock_err)

def demo_sw_operations(device):
    print("\n=== Software Upgrade Operations ===")
    sw_util = SW(device)
    try:
        print("Retrieving current Junos version...")
        current_version = sw_util.get_current_version()
        print("Current Junos version:", current_version)
    except Exception as e:
        print("Error retrieving software version:", e)

    # The following operations are potentially destructive. Uncomment and modify as needed.
    """
    try:
        package_file = "junos-install-package.tgz"  # Path to the software package
        print("Installing new software package:", package_file)
        install_result = sw_util.install(package=package_file, validate=True)
        print("Software installation result:\n", install_result)
    except Exception as e:
        print("Error during software installation:", e)
    """

    # Rebooting the device is destructive. Uncomment only in a controlled lab environment.
    """
    try:
        print("Rebooting the device...")
        sw_util.reboot()
        print("Device reboot initiated.")
    except Exception as e:
        print("Error during reboot:", e)
    """

    # Rolling back the software is also a critical operation. Uncomment if needed.
    """
    try:
        print("Rolling back to previous software version...")
        rollback_result = sw_util.rollback()
        print("Rollback result:\n", rollback_result)
    except Exception as e:
        print("Error during software rollback:", e)
    """

def demo_fs_operations(device):
    print("\n=== File System Operations ===")
    if FS is None:
        print("FS utility is not available in this PyEZ version.")
        return

    fs_util = FS(device)
    try:
        print("Listing filesystem details...")
        fs_details = fs_util.list_filesystem()
        print("Filesystem details:\n", fs_details)
    except Exception as e:
        print("Error listing filesystem:", e)

    # The following file operations are optional and require proper permissions.
    """
    try:
        # Example: Create a directory.
        dir_name = "/var/tmp/test_pyez_dir"
        print(f"Creating directory {dir_name}...")
        fs_util.file_mkdir(dir_name)
        print("Directory created.")
    except Exception as e:
        print("Error creating directory:", e)
    """
    """
    try:
        # Example: Copy a file from one location to another.
        source = "/var/tmp/source.txt"       # Ensure this file exists on the device.
        destination = "/var/tmp/destination.txt"
        print(f"Copying file from {source} to {destination}...")
        fs_util.file_copy(source, destination)
        print("File copied.")
    except Exception as e:
        print("Error copying file:", e)
    """
    """
    try:
        # Example: Delete a file.
        file_to_delete = "/var/tmp/destination.txt"
        print(f"Deleting file {file_to_delete}...")
        fs_util.file_delete(file_to_delete)
        print("File deleted.")
    except Exception as e:
        print("Error deleting file:", e)
    """

def main():
    # Replace with your device's connection details.
    hostname = "your_device_hostname_or_ip"
    username = "your_username"
    password = "your_password"

    print("Connecting to the device...")
    try:
        dev = Device(host=hostname, user=username, password=password)
        dev.open()
        print("Connected to device:", hostname)
    except Exception as e:
        print("Error connecting to device:", e)
        sys.exit(1)

    try:
        demo_device_facts(dev)
        demo_cli_commands(dev)
        demo_rpc_operations(dev)
        demo_config_operations(dev)
        demo_sw_operations(dev)
        demo_fs_operations(dev)
    finally:
        dev.close()
        print("\nDevice connection closed.")

if __name__ == '__main__':
    main()
