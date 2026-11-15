#!/usr/bin/env python3
"""Punto de entrada: sudo python3 auditor.py [--arreglar]"""
import sys

from auditor.cli import main

if __name__ == "__main__":
    sys.exit(main())
