from __future__ import annotations

import sys
from pathlib import Path

import pytest
import pytest_asyncio

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from tobira.lab import Lab  # noqa: E402
from tobira.pki import CertificateAuthority  # noqa: E402


@pytest.fixture
def ca(tmp_path: Path) -> CertificateAuthority:
    authority = CertificateAuthority(tmp_path / "pki")
    authority.ensure()
    return authority


@pytest_asyncio.fixture
async def lab(tmp_path: Path):
    """A fully wired lab: CA, four private apps, broker, two App Connectors."""
    instance = Lab(workdir=tmp_path / "lab")
    await instance.start()
    try:
        yield instance
    finally:
        await instance.stop()
