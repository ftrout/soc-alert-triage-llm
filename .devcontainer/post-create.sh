#!/bin/bash
# =============================================================================
# Post-create script for Kodiak SecOps 1 devcontainer
# =============================================================================

set -e

echo "=== Installing Kodiak SecOps 1 in development mode ==="
pip install -e ".[dev]"

echo ""
echo "=== Container setup complete! ==="
echo ""
echo "Optional: Install additional training dependencies:"
echo "  pip install deepspeed       # For distributed training"
echo "  pip install flash-attn      # For Flash Attention 2 (requires compilation)"
echo ""
echo "Quick start:"
echo "  python -m soc_triage_agent.data_generator --num-samples 100 --output data/train.jsonl"
echo "  pytest tests/"
echo ""
