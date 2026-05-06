"""Module entry point so `python -m arcis.cli` works the same as the
installed `arcis` command. Used by the Rust parity harness during
development; users continue to invoke `arcis` directly."""

from arcis.cli import main

if __name__ == "__main__":
    main()
