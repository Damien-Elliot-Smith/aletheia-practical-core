#!/usr/bin/env python3
from __future__ import annotations
import argparse
from pathlib import Path
from aletheia.veritas.session import VeritasShell

def build_parser():
    p = argparse.ArgumentParser(prog="veritas", description="Veritas deterministic claim session shell (no LLM).")
    p.add_argument("--root", required=True, help="Root directory that contains the Spine ledger (created via ag.py init)")
    p.add_argument("--claims-window", default="claims")
    p.add_argument("--sessions-window", default="sessions")
    return p

def main():
    args = build_parser().parse_args()
    shell = VeritasShell(Path(args.root), claims_window=args.claims_window, sessions_window=args.sessions_window)
    raise SystemExit(shell.run())

if __name__ == "__main__":
    main()
