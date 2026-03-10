#!/bin/bash
# --------------------------------------------------------------------------
# Guard Scanner CLI Sandbox Wrapper
# Description: Launch an AI agent safely confined to workspace-guard-scanner
# Author: Guava 🍈
# --------------------------------------------------------------------------
set -e

SANDBOX_DIR="$HOME/.openclaw/workspace-guard-scanner"
cd "$SANDBOX_DIR"

if [ ! -f "SESSION.md" ]; then
    echo "# Guard Scanner Dev Session" > SESSION.md
fi

echo "========================================================"
echo " 🛡️ Guard Scanner Sandbox Initiated"
echo " Workspace: $SANDBOX_DIR"
echo "========================================================"
echo ""

# Launch Gemini (or another configured CLI agent) restricted to this directory
gemini -p "You are the Guard Scanner Maintainer. Your workspace is strictly limited to $SANDBOX_DIR. Review SOUL.md and MEMORY.md, and then accomplish the following task. DO NOT touch parent directories. 1. Always write tests first. 2. Verify all modifications with npm run test." "$@" --yolo
