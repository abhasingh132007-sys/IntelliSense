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
import time

MAX_BUFFER_SIZE = 200
_buffer = deque(maxlen=MAX_BUFFER_SIZE)
_lock = threading.Lock()

# Simple packet-rate tracking for the dashboard stat card
_total_packet_count = 0


def add_packet(summary: dict):
    """
    summary must be a small JSON-serializable dict...
    """
    summary['_epoch'] = time.time()  # ADD THIS LINE - raw timestamp for bucketing, separate from the display 'time' string
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

def get_traffic_timeseries(own_ip, buckets=7, window_seconds=180):
    """
    Buckets recently captured packets into `buckets` time slots over the
    last `window_seconds`, split into incoming (dst == own_ip) vs outgoing
    (src == own_ip) - this is what feeds the "Live Traffic" chart.

    If own_ip is unknown (capture.py couldn't detect it), everything is
    counted as incoming rather than silently dropped, so the chart still
    shows real activity instead of going blank.
    """
    now = time.time()
    bucket_size = window_seconds / buckets
    incoming = [0] * buckets
    outgoing = [0] * buckets

    with _lock:
        packets = list(_buffer)

    for pkt in packets:
        epoch = pkt.get('_epoch')
        if epoch is None:
            continue
        age = now - epoch
        if age > window_seconds or age < 0:
            continue

        bucket_from_start = min(buckets - 1, int(age // bucket_size))
        idx = buckets - 1 - bucket_from_start  # age 0 (most recent) -> last bucket

        if own_ip and pkt.get('dst_ip') == own_ip:
            incoming[idx] += 1
        elif own_ip and pkt.get('src_ip') == own_ip:
            outgoing[idx] += 1
        else:
            incoming[idx] += 1

    labels = []
    for i in range(buckets):
        seconds_ago = (buckets - 1 - i) * bucket_size
        labels.append("now" if i == buckets - 1 else f"-{int(seconds_ago)}s")

    return {"labels": labels, "incoming": incoming, "outgoing": outgoing}