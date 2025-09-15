#!/usr/bin/env python3
"""
Complete Example Program Using Napalm's Junos Driver

This script demonstrates various Junos operations using Napalm, including:
  - Retrieving device facts
  - Retrieving the running configuration
  - Gathering interface details and counters
  - Retrieving ARP table, BGP neighbor information, LLDP neighbors, routing,
    MAC address table, environmental data, and optics information
  - Executing a CLI command (e.g., "show version")
  - Performing ping and traceroute tests
  - Loading a candidate configuration as a merge candidate, comparing, and discarding it

Before running, update:
  - hostname, username, and password with your lab device's details.
  - candidate configuration if needed.
"""

from napalm import get_network_driver
import sys

def demo_get_facts(device):
    facts = device.get_facts()
    print("\n--- Device Facts ---")
    for key, value in facts.items():
        print(f"{key}: {value}")

def demo_get_config(device):
    config = device.get_config(retrieve="running")
    print("\n--- Running Configuration ---")
    print(config["running"])

def demo_get_interfaces(device):
    interfaces = device.get_interfaces()
    print("\n--- Interfaces ---")
    for interface, details in interfaces.items():
        print(f"{interface}: {details}")

def demo_get_interfaces_counters(device):
    counters = device.get_interfaces_counters()
    print("\n--- Interface Counters ---")
    for interface, details in counters.items():
        print(f"{interface}: {details}")

def demo_get_arp_table(device):
    arp = device.get_arp_table()
    print("\n--- ARP Table ---")
    for entry in arp:
        print(entry)

def demo_get_bgp_neighbors(device):
    bgp = device.get_bgp_neighbors()
    print("\n--- BGP Neighbors ---")
    print(bgp)

def demo_get_bgp_neighbors_detail(device):
    bgp_detail = device.get_bgp_neighbors_detail()
    print("\n--- BGP Neighbors Detail ---")
    print(bgp_detail)

def demo_get_lldp_neighbors(device):
    lldp = device.get_lldp_neighbors()
    print("\n--- LLDP Neighbors ---")
    print(lldp)

def demo_get_route_to(device, destination="8.8.8.8"):
    routes = device.get_route_to(destination)
    print(f"\n--- Routes to {destination} ---")
    print(routes)

def demo_get_mac_address_table(device):
    mac_table = device.get_mac_address_table()
    print("\n--- MAC Address Table ---")
    print(mac_table)

def demo_get_environment(device):
    environment = device.get_environment()
    print("\n--- Environment ---")
    print(environment)

def demo_get_optics(device):
    try:
        optics = device.get_optics()
        print("\n--- Optical Transceivers ---")
        print(optics)
    except NotImplementedError:
        print("\nOptics information is not supported on this device.")

def demo_cli(device):
    cli_output = device.cli(["show version"])
    print("\n--- CLI Output (show version) ---")
    print(cli_output)

def demo_ping(device, destination="8.8.8.8"):
    ping_result = device.ping(destination=destination)
    print("\n--- Ping Result ---")
    print(ping_result)

def demo_traceroute(device, destination="8.8.8.8"):
    try:
        traceroute_result = device.traceroute(destination=destination)
        print("\n--- Traceroute Result ---")
        print(traceroute_result)
    except NotImplementedError:
        print("\nTraceroute is not supported on this device.")

def demo_config_operations(device, candidate_config):
    """
    Demonstrates configuration operations:
      - Load merge candidate configuration
      - Compare candidate with the running config
      - Discard the candidate configuration to avoid committing changes
    """
    print("\n--- Configuration Operations Demo ---")
    try:
        print("Loading merge candidate configuration...")
        device.load_merge_candidate(config=candidate_config)
        diff = device.compare_config()
        print("Configuration Diff:")
        print(diff)
        print("Discarding candidate configuration...")
        device.discard_config()
    except Exception as err:
        print("Error during configuration operations:", err)
        try:
            device.discard_config()
        except Exception as discard_err:
            print("Error discarding candidate configuration:", discard_err)

def main():
    # Device connection details: update these with your device info.
    hostname = "10.85.172.83"  # Replace with your device's IP address
    username = "root"           # Replace with your username
    password = "Juniper"        # Replace with your password

    # Initialize the Napalm Junos driver
    driver = get_network_driver("junos")
    device = driver(hostname=hostname, username=username, password=password, timeout=180)

    try:
        print("Connecting to the device...")
        device.open()
        print("Connection established.")
    except Exception as conn_err:
        print("Error connecting to device:", conn_err)
        sys.exit(1)

    try:
        # Operational Data Examples
        demo_get_facts(device)
        demo_get_config(device)
        demo_get_interfaces(device)
        demo_get_interfaces_counters(device)
        demo_get_arp_table(device)
        demo_get_bgp_neighbors(device)
        demo_get_bgp_neighbors_detail(device)
        demo_get_lldp_neighbors(device)
        demo_get_route_to(device, destination="8.8.8.8")
        demo_get_mac_address_table(device)
        demo_get_environment(device)
        demo_get_optics(device)
        demo_cli(device)
        demo_ping(device, destination="8.8.8.8")
        demo_traceroute(device, destination="8.8.8.8")

        # Configuration Operations Example
        # The candidate config may be loaded from a file. Here, we use a simple inline string.
        # If you have a file, you can uncomment the following lines:
        #
        # with open("config_file") as f:
        #     candidate_config = f.read()
        #
        # For demonstration, we use a simple config that changes the hostname.
        candidate_config = """
system {
    host-name demo_device;
}
"""
        demo_config_operations(device, candidate_config)
    except Exception as e:
        print("An error occurred:", e)
    finally:
        device.close()
        print("Connection closed.")

if __name__ == '__main__':
    main()
