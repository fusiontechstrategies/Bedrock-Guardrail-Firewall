"""Create a fresh private Windows state leaf without repairing existing paths."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import orchestrator as app


class PrivateTemporaryDirectory:
    """Keep cleanup ownership of the outer temporary directory and private leaf."""

    def __init__(self, *args, **kwargs):
        self._parent = tempfile.TemporaryDirectory(*args, **kwargs)
        self.name = self._parent.name
        if os.name == "nt":
            leaf = Path(self.name) / "private-state"
            try:
                # The creation descriptor explicitly sets TokenUser as owner.
                # An elevated token's default Administrators owner is not used.
                descriptor = app._open_private_key(leaf, create=True, directory=True)
                os.close(descriptor)
            except BaseException:
                self._parent.cleanup()
                raise
            self.name = str(leaf)

    def __enter__(self):
        return self.name

    def __exit__(self, *args):
        self.cleanup()

    def cleanup(self):
        self._parent.cleanup()
