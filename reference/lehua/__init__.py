"""Minimal, read-only LeHua protocol reference implementation.

SPDX-License-Identifier: CC-BY-SA-4.0
"""

from .client import Client
from .codec import ProtocolError
from . import packets

__all__ = ["Client", "ProtocolError", "packets"]
