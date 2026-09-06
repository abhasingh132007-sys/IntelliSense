"""
packet_buffer.py
-----------------
Keeps a rolling in-memory buffer of the most recently captured packets.

Why a buffer instead of hitting Scapy/the DB directly on every dashboard
request: sniff() runs continuously in its own background thread, and the
Flask request thread needs a fast, safe way to read the "latest state"
without blocking or racing with the capture thread. A deque with a lock
solves both problems cheaply.

This is intentionally almost identical to mock_data.get_live_packets() in
shape - that's what let us swap them out with a one-line change in app.py.
"""

from collections import deque
import threading

MAX_BUFFER_SIZE = 200
_buffer = deque(maxlen=MAX_BUFFER_SIZE)
_lock = threading.Lock()

# Simple packet-rate tracking for the dashboard stat card
_total_packet_count = 0


def add_packet(summary: dict):
    """
    summary must be a small JSON-serializable dict (never a raw Scapy
    packet object - those aren't JSON safe and expose more than needed).
    """
    global _total_packet_count
    with _lock:
        _buffer.append(summary)
        _total_packet_count += 1


def get_recent_packets():
    with _lock:
        return list(reversed(_buffer))  # most recent first, matches mock_data's ordering


def get_total_count():
    with _lock:
        return _total_packet_count


def clear():
    """Mainly useful for testing - wipes the buffer and resets the counter."""
    global _total_packet_count
    with _lock:
        _buffer.clear()
        _total_packet_count = 0
