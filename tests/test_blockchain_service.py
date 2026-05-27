import uuid
from datetime import datetime, timezone

import pytest

pytest.importorskip("web3")

import app.models.register  # noqa: F401 - ensure SQLAlchemy mappers are registered
from app.models.ioc import IOC, IOCStatus, IOCType
from app.services.blockchain_service import BlockchainService


def _build_ioc(*, tags: list[str], status: IOCStatus, submitted_at: datetime) -> IOC:
    return IOC(
        id=uuid.UUID("1cebed67-1f81-4d20-a8c9-e2f1b4fe9410"),
        type=IOCType.IP,
        value="185.220.101.45",
        description="Known scanner",
        org_id=uuid.UUID("9f0f16d2-5d00-4f1f-9f84-2da95a5b9de1"),
        tlp="green",
        confidence=80,
        first_seen=datetime(2026, 4, 3, 10, 5, tzinfo=timezone.utc),
        last_seen=datetime(2026, 4, 4, 9, 30, tzinfo=timezone.utc),
        tags=tags,
        source_context="firewall",
        status=status,
        submitted_at=submitted_at,
        validated_at=datetime(2026, 4, 5, 9, 30, tzinfo=timezone.utc),
    )


def test_compute_ioc_content_hash_is_deterministic_for_equivalent_payload():
    ioc_a = _build_ioc(
        tags=["scanner", "botnet", "scanner"],
        status=IOCStatus.APPROVED,
        submitted_at=datetime(2026, 4, 5, 10, 0, tzinfo=timezone.utc),
    )
    ioc_b = _build_ioc(
        tags=["botnet", "scanner"],
        status=IOCStatus.FALSE_POSITIVE,
        submitted_at=datetime(2026, 5, 5, 10, 0, tzinfo=timezone.utc),
    )

    hash_a = BlockchainService.compute_ioc_content_hash_bytes32(ioc_a)
    hash_b = BlockchainService.compute_ioc_content_hash_bytes32(ioc_b)

    assert isinstance(hash_a, bytes)
    assert len(hash_a) == 32
    assert hash_a == hash_b


def test_ioc_uuid_to_bytes32_is_stable():
    ioc_id = uuid.UUID("1cebed67-1f81-4d20-a8c9-e2f1b4fe9410")
    value = BlockchainService.ioc_uuid_to_bytes32(ioc_id)
    assert isinstance(value, bytes)
    assert len(value) == 32
    assert value[:16] == ioc_id.bytes
    assert value[16:] == (b"\x00" * 16)
