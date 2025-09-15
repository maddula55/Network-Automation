#!/usr/bin/env python3
"""
Usage:
  python3 generate_image_and_upgrade.py \
    --devices devices.yml \
    --images images.yml \
    [--select <name_or_id>|all] \
    [--upgrade]

This script will:
 1. Load device inventory (YAML or CSV) containing:
      - name, id, host, user, password
 2. Load image definitions YAML containing entries with:
      - platforms      (string or list of strings; required)
      - code_version   (string; required)
      - template       (string with "{version}" placeholder; required)
      - vmhost         (boolean; defaults to false)
      - flex           ("flex"/"non-flex"; defaults to "non-flex")
      - re_model       (string; optional)
      - location       (string URL or path; optional)
 3. Select one or all devices by name or id.
 4. For each device:
      a. Connect and retrieve device facts: model, junos_version, junos_type, vmhost flag.
      b. Determine re_model: for srx1500 based on version (old/new), else from chassis-inventory model-number.
      c. Match image definition entry where device_model is in entry['platforms'].
      d. Generate image_name from template: template.format(version=junos_version).
      e. Construct full_image_path: location + '/' + image_name if location exists, else image_name.
      f. If --upgrade: transfer image, install, and reboot; else print device info and image details.

Dependencies:
  pip install junos-eznc pyyaml pandas
"""
import argparse
import sys
import getpass
import yaml
import csv
from jnpr.junos import Device
from jnpr.junos.exception import ConnectError, RpcError


def load_devices(path):
    """Load devices from YAML or CSV file."""
    devices = []
    if path.lower().endswith(('.yml', '.yaml')):
        with open(path) as f:
            data = yaml.safe_load(f)
        devices = data.get('devices', [])
    else:
        with open(path) as f:
            reader = csv.DictReader(f)
            devices = [row for row in reader]
    return devices


def load_images(path):
    """Load image definitions from YAML file. Normalizes 'platforms' to a list."""
    with open(path) as f:
        data = yaml.safe_load(f)
    raw = data.get('images', [])

    images = []
    for idx, img in enumerate(raw):
        # Required fields
        if 'code_version' not in img or 'template' not in img:
            print(f"Error: image entry #{idx} missing required key 'code_version' or 'template'", file=sys.stderr)
            sys.exit(1)
        # Normalize platforms
        plats = []
        if 'platforms' in img:
            plats = img['platforms']
        elif 'platform' in img:
            plats = [img['platform']]
        else:
            print(f"Error: image entry #{idx} missing 'platforms' or 'platform'", file=sys.stderr)
            sys.exit(1)
        if isinstance(plats, str):
            plats = [plats]
        plats = [p.strip().lower() for p in plats]

        entry = {
            'platforms': plats,
            'code_version': img['code_version'].strip(),
            'vmhost': bool(img.get('vmhost', False)),
            'flex': img.get('flex', 'non-flex').strip().lower(),
            're_model': img.get('re_model', None).strip().lower() if img.get('re_model') else None,
            'template': img['template'].strip(),
            'location': img.get('location', '').rstrip('/')
        }
        images.append(entry)
    return images


def select_devices(devices, selector):
    """Return devices matching name or id, or all if selector=='all'."""
    if selector.lower() == 'all':
        return devices
    return [d for d in devices if d.get('name') == selector or d.get('id') == selector]


def parse_version_and_type(dev):
    """Retrieve Junos version and type via RPC."""
    txt = dev.rpc.cli('show version', format='text').text
    version, dev_type = None, 'non-flex'
    for line in txt.splitlines():
        line = line.strip()
        if line.startswith('Junos:'):
            parts = line.split(':',1)[1].strip().split()
            version = parts[0]
            if len(parts) > 1:
                dev_type = parts[1].lower()
            break
    if not version:
        raise RuntimeError('Failed to parse Junos version')
    return version, dev_type


def extract_re_model(dev, model, version):
    """
    Determine re_model:
      - if model=='srx1500': 'old' if version.startswith('15.1X49') else 'new'
      - else: fetch chassis-inventory model-number for Routing Engine 0/1
    """
    if model == 'srx1500':
        return 'old' if version.startswith('15.1X49') else 'new'

    try:
        inv = dev.rpc.get_chassis_inventory()
    except RpcError:
        return None

    for slot in ('Routing Engine 0','Routing Engine 1'):
        xpath = (
            "//*[local-name()='chassis-module']["
            "*[local-name()='name' and normalize-space(text())=$slot]]"
            "/*[local-name()='model-number']/text()"
        )
        res = inv.xpath(xpath, slot=slot)
        if res:
            text = res[0].strip()
            if text:
                return text.lower()
    return None


def find_image(images, platform, code_version, vmhost, flex, re_model):
    """Match an image entry based on device attributes."""
    for img in images:
        if platform.lower() not in img['platforms']:
            continue
        if img['code_version'] != code_version:
            continue
        if img['vmhost'] != vmhost:
            continue
        if img['flex'] != flex:
            continue
        if img['re_model'] and img['re_model'] != (re_model or '').lower():
            continue
        return img
    return None


def main():
    parser = argparse.ArgumentParser(
        description='Generate image name and optionally upgrade devices')
    parser.add_argument('--devices', required=True)
    parser.add_argument('--images', required=True)
    parser.add_argument('--select', default='all')
    parser.add_argument('--upgrade', action='store_true')
    args = parser.parse_args()

    devices = load_devices(args.devices)
    images = load_images(args.images)
    selected = select_devices(devices, args.select)
    if not selected:
        print('No matching devices.'); sys.exit(1)

    for d in selected:
        name = d.get('name')
        host = d.get('host')
        user = d.get('user')
        pwd = d.get('password') or getpass.getpass(f"Password for {name}: ")
        try:
            dev = Device(host=host, user=user, passwd=pwd)
            dev.open()

            model = dev.facts.get('model','').lower()
            version, dev_type = parse_version_and_type(dev)
            vmhost = bool(dev.facts.get('vmhost', False))
            re_model = extract_re_model(dev, model, version)

            entry = find_image(images, model, version, vmhost, dev_type, re_model)
            if not entry:
                raise RuntimeError(f"No image definition for {model} {version} {dev_type} re={re_model}")

            image_name = entry['template'].format(version=version)
            location = entry['location']
            full_path = f"{location}/{image_name}" if location else image_name

            if args.upgrade:
                print(f"Upgrading {name}: transferring {full_path}...")
                dev.rpc.request_transfer(**{'filename': full_path, 'progress': 'true'})
                dev.rpc.request_system_sw_add(package=image_name)
                dev.rpc.request_reboot()
            else:
                print(f"{name}: version={version}, model={model}, type={dev_type}, re={re_model}\n" +
                      f"    image: {image_name}\n    location: {location or '(none)'}")

            dev.close()
        except Exception as e:
            print(f"{name}: ERROR: {e}")

if __name__ == '__main__':
    main()
