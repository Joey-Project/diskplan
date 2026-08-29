#!/usr/bin/python3
"""Exit the leader while one selected descendant remains until SIGKILL."""

import os
import signal
import sys


if len(sys.argv) != 2 or sys.argv[1] not in {"writer", "silent"}:
    raise RuntimeError("expected writer or silent descendant mode")
ready_reader, ready_writer = os.pipe()
descendant = os.fork()
if descendant == 0:
    os.close(ready_reader)
    if sys.argv[1] == "silent":
        os.close(1)
    os.close(2)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    os.write(ready_writer, b"1")
    os.close(ready_writer)
    while True:
        signal.pause()

os.close(ready_writer)
if os.read(ready_reader, 1) != b"1":
    raise RuntimeError("descendant did not install its signal handler")
os.close(ready_reader)
