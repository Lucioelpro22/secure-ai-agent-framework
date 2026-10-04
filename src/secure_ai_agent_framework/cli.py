"""Minimal CLI for smoke-checking policy definitions."""

from __future__ import annotations

import argparse


def main() -> int:
    parser = argparse.ArgumentParser(description="Secure AI agent policy utilities")
    parser.add_argument("--version", action="version", version="0.1.0")
    parser.parse_args()
    return 0
