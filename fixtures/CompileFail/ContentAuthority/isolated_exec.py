#!/usr/bin/python3
"""Create a private process group, then execute one compile-fail fixture command."""

import os
import sys


try:
    os.setsid()
except PermissionError:
    # Foundation Process can launch the wrapper as an isolated process-group leader.
    # In that exact state setsid(2) must fail with EPERM, but group cleanup remains safe.
    if os.getpgrp() != os.getpid():
        raise
os.execv(sys.argv[1], sys.argv[1:])
