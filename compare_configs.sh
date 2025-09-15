#!/bin/bash
# Usage: ./compare_configs.sh <old_conf> <new_conf>
# Example: ./compare_configs.sh juniper.conf_set juniper.conf.1_set

OLD="$1"
NEW="$2"

# Show lines that appear in NEW but not in OLD (added)
echo "=== Lines added in $NEW (not in $OLD) ==="
grep -F -x -v -f "$OLD" "$NEW"

# Show lines that appear in OLD but not in NEW (removed)
echo ""
echo "=== Lines removed from $OLD (not in $NEW) ==="
grep -F -x -v -f "$NEW" "$OLD"

