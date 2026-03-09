"""
Functional end-to-end test for a Linux client connecting to a remote x64dbg instance.

Usage:
    python tests/test_functional_remote.py [host] [req_rep_port] [pub_sub_port]

Defaults: 192.168.145.130:27066/27067

This is a standalone script, not managed by pytest.
"""

import sys

from x64dbg_automate import X64DbgClient


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.145.130"
    req_rep_port = int(sys.argv[2]) if len(sys.argv) > 2 else 27066
    pub_sub_port = int(sys.argv[3]) if len(sys.argv) > 3 else 27067

    print(f"Connecting to {host}:{req_rep_port}/{pub_sub_port} ...")
    client = X64DbgClient.connect_remote(host, req_rep_port, pub_sub_port)

    # Check that something is loaded (is_debugging returns True)
    debugging = client.is_debugging()
    print(f"is_debugging: {debugging}")
    assert debugging, "Expected debugger to have something loaded (is_debugging() == True)"

    # Check that CIP > 0
    cip_value, success = client.eval_sync("cip")
    print(f"CIP: {hex(cip_value)} (eval success: {success})")
    assert success, "eval_sync('cip') failed"
    assert cip_value > 0, f"Expected CIP > 0, got {hex(cip_value)}"

    client.detach_session()
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"FAIL: {e}", file=sys.stderr)
        sys.exit(1)
