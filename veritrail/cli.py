"""
veritrail.cli
=============
A small operator CLI. Deliberately minimal — the heavy lifting is the SDK and
the REST service; this just covers the things an operator does at a terminal.

    veritrail keygen            generate an Ed25519 keypair (prints public, and
                                writes the private key to a 0600 file)
    veritrail serve             run the REST API (uvicorn)
    veritrail demo              run the end-to-end demo
    veritrail version           print the version
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__, crypto


def _keygen(args: argparse.Namespace) -> int:
    priv, pub = crypto.generate_keypair()
    pub_b64 = crypto.public_key_to_b64(pub)
    print(f"public_key_b64: {pub_b64}")
    if args.out:
        # Write private key with restrictive permissions; never print it.
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(crypto.private_key_to_b64(priv))
        print(f"private key written to {args.out} (mode 0600) — keep it secret")
    else:
        print("(re-run with --out PATH to persist the private key to a 0600 file)")
    return 0


def _serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        print("uvicorn is required to serve; pip install 'uvicorn[standard]'", file=sys.stderr)
        return 1
    uvicorn.run("veritrail.api.server:app", host=args.host, port=args.port)
    return 0


def _demo(_args: argparse.Namespace) -> int:
    from examples.demo import main as demo_main
    demo_main()
    return 0


def _version(_args: argparse.Namespace) -> int:
    print(f"veritrail {__version__}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="veritrail", description="Veritrail operator CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_keygen = sub.add_parser("keygen", help="generate an Ed25519 keypair")
    p_keygen.add_argument("--out", help="path to write the private key (0600)")
    p_keygen.set_defaults(func=_keygen)

    p_serve = sub.add_parser("serve", help="run the REST API")
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8080)
    p_serve.set_defaults(func=_serve)

    p_demo = sub.add_parser("demo", help="run the end-to-end demo")
    p_demo.set_defaults(func=_demo)

    p_version = sub.add_parser("version", help="print version")
    p_version.set_defaults(func=_version)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
