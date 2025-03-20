from __future__ import annotations
from typing import Dict, List
import argparse as ap
import binaryninja as bn
import hashlib as hl
import json as json


def main() -> None:
    """
    This function is used to process a given binary in headless mode.
    """
    # Parse arguments
    description = """
    Funalyzer is a Binary Ninja plugin that tries to detect functions from libraries 
    based on the objects files of these libraries. The plugin can be run both in 
    Binary Ninja and in headless mode.
    """
    parser = ap.ArgumentParser(
        description=description, formatter_class=ap.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument("infile")
    parser.add_argument("outfile")
    parser.add_argument("--debug", action="store_true")

    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        "-U", dest="mode_normal", action="store_true", help="Unblobulate!"
    )
    modes.add_argument("-X", dest="mode_extract", action="store_true", help="Extract")
    modes.add_argument(
        "-B",
        dest="mode_build",
        action="store_true",
        help="Build library signatures (provide input directory and output LMDB filename)",
    )

    input_opts = parser.add_argument_group("Input options")
    input_opts.add_argument(
        "--base-address",
        type=int,
        help="Manually specify the base address of the binary",
    )
    input_opts.add_argument(
        "--entry-point", type=int, help="Manually specify the entry point of the binary"
    )
    input_opts.add_argument("--arch", help="Manually specify the architecture to use")
    input_opts.add_argument(
        "--cortex", help="Fast Cortex-M loading mode", action="store_true"
    )

    symbol_opts = parser.add_argument_group("Symbol Recovery Options")
    symbol_opts.add_argument(
        "-S",
        "--disable-symbol-recovery",
        help="Enable symbol recovery",
        action="store_true",
    )
    symbol_opts.add_argument(
        "-F",
        "--fudge-factor",
        help="Lowest similarity score to consider a 'match' for symbol recovery",
    )
    symbol_opts.add_argument(
        "-L", "--lmdb", help="LMDB file to use for symbol recovery"
    )
    symbol_opts.add_argument(
        "-1",
        "--first-order",
        help="Only use the first-order metric to gather symbols",
        action="store_true",
    )
    symbol_opts.add_argument(
        "-2",
        "--second-order",
        help="Only use the third-order metric to gather symbols",
        action="store_true",
    )
    symbol_opts.add_argument(
        "-3",
        "--third-order",
        help="Only use the third-order metric to gather symbols",
        action="store_true",
    )
    symbol_opts.add_argument(
        "--scoring",
        help="Enable scoring mode, use a binary with symbols to score symbol recovery accuracy",
        action="store_true",
    )

    output_opts = parser.add_argument_group("Output Options")
    output_opts.add_argument(
        "-E", "--elf", help="Produce an ELF (Default)", action="store_true"
    )
    output_opts.add_argument(
        "-Y", "--yaml", help="Produce a YAML file", action="store_true"
    )

    args = parser.parse_args()
    print(args)


if __name__ == "__main__":
    main()
