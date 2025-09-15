#!/usr/bin/env python3
"""
This script demonstrates device management operations for a Junos device using PyEZ.
It uses the SW utility (jnpr.junos.utils.sw) to perform upgrade-related functions:
  - Retrieve the current software version.
  - Install a new software package.
  - Reboot the device.
  - Rollback to a previous software version.

Update the hostname, username, password, and package file as needed.
"""

from jnpr.junos import Device
from jnpr.junos.utils.sw import SW
import sys

def get_current_version(sw_obj):
    try:
        current_version = sw_obj.get_current_version()
        print("Current Junos version:", current_version)
    except Exception as e:
        print("Error retrieving current version:", e)

def install_software(sw_obj, package_file):
    try:
        print("Starting software installation using package:", package_file)
        # The install() method will copy the package (if needed), validate it,
        # and initiate the installation process.
        result = sw_obj.install(package=package_file, validate=True)
        print("Software installation result:")
        print(result)
    except Exception as e:
        print("Error during software installation:", e)

def reboot_device(sw_obj):
    try:
        print("Rebooting the device...")
        sw_obj.reboot()
        print("Reboot initiated. Device may take several minutes to come back online.")
    except Exception as e:
        print("Error during reboot:", e)

def rollback_software(sw_obj):
    try:
        print("Rolling back to the previous software version...")
        result = sw_obj.rollback()
        print("Rollback result:")
        print(result)
    except Exception as e:
        print("Error during software rollback:", e)

def main():
    # Update these with your device's connection details.
    hostname = "your_device_hostname_or_ip"
    username = "your_username"
    password = "your_password"
    
    # Connect to the device
    dev = Device(host=hostname, user=username, password=password)
    try:
        dev.open()
        print("Connected to device:", hostname)
    except Exception as e:
        print("Error connecting to device:", e)
        sys.exit(1)
    
    # Create the SW utility object for software operations.
    sw_obj = SW(dev)
    
    # 1. Retrieve and display the current Junos software version.
    print("\n== Retrieving current software version ==")
    get_current_version(sw_obj)
    
    # 2. Install a new software package.
    # Replace 'junos-install-package.tgz' with the path to your new software package.
    package_file = "junos-install-package.tgz"
    print("\n== Installing new software package ==")
    install_software(sw_obj, package_file)
    
    # 3. (Optional) Reboot the device after installation.
    # Uncomment the line below to initiate a reboot.
    # print("\n== Rebooting the device ==")
    # reboot_device(sw_obj)
    
    # 4. (Optional) Rollback to the previous software version.
    # Uncomment the line below to rollback.
    # print("\n== Rolling back to previous software version ==")
    # rollback_software(sw_obj)
    
    # Close the device connection
    dev.close()
    print("Device connection closed.")

if __name__ == '__main__':
    main()
