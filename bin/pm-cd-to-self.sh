#!/bin/bash

echo "Usage: source pm-cd-to-self.sh"

# Get the full path of the script itself
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Change directory to that location
cd "$SCRIPT_DIR" || {
  echo "Failed to cd into script directory: $SCRIPT_DIR"
  exit 1
}

# Confirm where we are
echo "Now in: $(pwd)"