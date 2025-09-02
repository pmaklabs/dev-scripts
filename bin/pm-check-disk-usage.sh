#!/bin/bash

# List of suffixes per host
SUFFIXES=("dev-1" "test-1")

# Column widths
W_PROJECT=10
W_DEV=20
W_TEST=20

# Print table header
printf "%-${W_PROJECT}s %-${W_DEV}s %-${W_TEST}s\n" "Project" "Dev Usage" "Test Usage"
printf "%-${W_PROJECT}s %-${W_DEV}s %-${W_TEST}s\n" "--------" "-------------------" "-------------------"

# Loop through each project
for project in "$@"; do
  # Initialize row content
  row_dev="ERROR"
  row_test="ERROR"

  # Loop through each suffix
  for suffix in "${SUFFIXES[@]}"; do
    host="${project}-${suffix}"

    # SSH and get disk usage
    usage=$(ssh -o ConnectTimeout=5 -o BatchMode=yes "$host" "df -h / 2>/dev/null | awk 'NR==2 {print \$3\"/\"\$2\" (\"\$5\")\"}'")

    # Store result
    if [[ "$suffix" == "dev-1" ]]; then
      row_dev=${usage:-ERROR}
    else
      row_test=${usage:-ERROR}
    fi
  done

  # Print aligned row
  printf "%-${W_PROJECT}s %-${W_DEV}s %-${W_TEST}s\n" "$project" "$row_dev" "$row_test"
done