"""PyInstaller entry point; imports only the closed COH helper package."""

from coh_pysigma_helper.__main__ import main


if __name__ == "__main__":
    raise SystemExit(main())
