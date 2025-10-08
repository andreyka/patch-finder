"""Command-line tool for the patch finder agent."""

from __future__ import annotations

import argparse
import json

from agent import run_agent
from config import DEFAULT_BASE_URL, DEFAULT_MODEL


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser.
    
    Returns:
        An ArgumentParser configured with all CLI options.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Find the official upstream fix commit for a CVE "
            "(128k context agent)."
        )
    )
    parser.add_argument("cve_id")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--steps", type=int, default=60)
    parser.add_argument("--debug", action="store_true")
    return parser


def main() -> None:
    """Main entry point for the CLI."""
    parser = build_arg_parser()
    args = parser.parse_args()
    result = run_agent(
        args.cve_id, args.model, args.base_url, args.steps, args.debug
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
