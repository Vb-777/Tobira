"""Tobira - a zero trust private access lab.

Tobira (扉, "door") rebuilds the private-access model used by commercial zero
trust platforms: both the application side and the user side dial *outbound* to
a broker, so private applications expose no inbound listening ports and cannot
be discovered or attacked from the network.

Every connection is authorised individually against identity, device posture and
policy, and every decision is written to a SIEM-ready audit stream.
"""

__version__ = "1.0.0"

__all__ = ["__version__"]
