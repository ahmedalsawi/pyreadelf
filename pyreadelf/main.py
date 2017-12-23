#!/usr/bin/env python

import argparse

from elf import *

def main():
    parser = argparse.ArgumentParser(description='readelf-like implementation in python')
    parser.add_argument("file_name", type=str, help="elf file")
    args = parser.parse_args()

    e = ElfParser(args.file_name)

if __name__ == "__main__":
    main()
