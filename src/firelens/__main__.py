"""
Entry point for running FireLens as a module: python -m firelens
"""
import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
