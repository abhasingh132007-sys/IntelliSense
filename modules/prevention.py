"""
prevention.py
--------------
Blocks/unblocks IPs via iptables. This is what turns an Administrator's
"Approve" click into a real firewall rule - closing the loop your
architecture doc describes:
    Approve Block -> Python -> iptables -> Malicious IP Blocked

Requires root privileges (iptables modifies kernel firewall tables), so
the Flask app needs to run with sudo, OR your user needs passwordless
sudo scoped to iptables specifically (see the sudoers setup note at the
bottom of this file).

Design notes:
- Every function is wrapped so a failure (no sudo, iptables missing,
  wrong permissions) never crashes the calling route - it returns a
  result dict with success=False and a reason instead. An incident
  approval should never 500 just because the firewall call failed;
  the incident status still updates, and the failure gets surfaced to
  the Administrator instead of silently vanishing.
- IP addresses are validated before ever reaching subprocess, and all
  subprocess calls use argument LISTS (never a shell string), so a
  malformed/malicious IP can't inject extra shell commands.
"""

import subprocess
import re

IPTABLES = "/usr/sbin/iptables"  # confirm with `which iptables` on your VM; /sbin/iptables on some distros

IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def is_valid_ip(ip):
    if not ip or not IP_PATTERN.match(ip):
        return False
    return all(0 <= int(octet) <= 255 for octet in ip.split("."))


def _run_iptables(args):
    """
    Runs an iptables command, returns (success: bool, output_or_error: str).
    Never raises - callers always get a clean result to act on.
    """
    try:
        result = subprocess.run(
            ["sudo", IPTABLES] + args,
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return True, result.stdout
        return False, result.stderr.strip() or f"iptables exited with code {result.returncode}"
    except FileNotFoundError:
        return False, "iptables not found on this system"
    except subprocess.TimeoutExpired:
        return False, "iptables command timed out"
    except Exception as e:
        return False, str(e)


def is_ip_blocked(ip_address):
    if not is_valid_ip(ip_address):
        return False
    success, _ = _run_iptables(["-C", "INPUT", "-s", ip_address, "-j", "DROP"])
    return success  # -C (check) exits 0 if the rule exists, 1 if it doesn't


def block_ip(ip_address, reason=""):
    """
    Adds a DROP rule for the given IP, unless it's already blocked.
    Returns a dict: {"success": bool, "already_blocked": bool, "error": str|None}
    """
    if not is_valid_ip(ip_address):
        return {"success": False, "already_blocked": False, "error": f"Invalid IP address: {ip_address}"}

    if is_ip_blocked(ip_address):
        return {"success": True, "already_blocked": True, "error": None}

    success, output = _run_iptables(["-A", "INPUT", "-s", ip_address, "-j", "DROP"])
    return {"success": success, "already_blocked": False, "error": None if success else output}


def unblock_ip(ip_address):
    """
    Removes the DROP rule for the given IP.
    Returns a dict: {"success": bool, "was_blocked": bool, "error": str|None}
    """
    if not is_valid_ip(ip_address):
        return {"success": False, "was_blocked": False, "error": f"Invalid IP address: {ip_address}"}

    if not is_ip_blocked(ip_address):
        return {"success": True, "was_blocked": False, "error": None}

    success, output = _run_iptables(["-D", "INPUT", "-s", ip_address, "-j", "DROP"])
    return {"success": success, "was_blocked": True, "error": None if success else output}


def list_blocked_ips():
    """
    Parses `iptables -L INPUT -n` to return currently blocked IPs.
    Returns a list of IP strings, or an empty list if iptables isn't
    accessible (e.g. running without sudo) - callers should treat an
    empty list as "unknown", not necessarily "nothing is blocked".
    """
    success, output = _run_iptables(["-L", "INPUT", "-n"])
    if not success:
        return []

    blocked = []
    for line in output.splitlines():
        if "DROP" in line:
            parts = line.split()
            if len(parts) >= 4 and is_valid_ip(parts[3]):
                blocked.append(parts[3])
    return blocked


# ---------------------------------------------------------------------------
# One-time setup note (not code that runs - just documentation for you):
#
# For block_ip/unblock_ip to work WITHOUT typing a sudo password every time
# Flask calls them, grant passwordless sudo scoped to iptables only:
#
#   sudo visudo -f /etc/sudoers.d/intellisense
#
# Add this line (replace 'abha' with your actual username):
#   abha ALL=(ALL) NOPASSWD: /usr/sbin/iptables
#
# Verify with: sudo -l
# You should see the iptables line listed under NOPASSWD.
#
# Alternatively, just always run the whole Flask app with sudo
# (sudo $(which python3) app.py) - simpler, but means Scapy AND iptables
# calls both run as root for the life of the process.
# ---------------------------------------------------------------------------