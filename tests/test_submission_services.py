import uuid

import pytest
from fastapi import HTTPException

import app.models.register  # noqa: F401 - ensure SQLAlchemy mappers are registered
from app.models.malware_sample import MalwareFamily, MalwareStatus
from app.models.threat_actor import Motivation, ThreatActorStatus
from app.schemas.malware import MalwareCreate
from app.schemas.threat_actor import ThreatActorCreate
from app.services.malware_service import MalwareService
from app.services.threat_actor_service import ThreatActorService


class _FakeScalarResult:
    def __init__(self, items):
        self._items = items

    def first(self):
        return self._items[0] if self._items else None

    def all(self):
        return list(self._items)


class _FakeResult:
    def __init__(self, items):
        self._items = items

    def scalars(self):
        return _FakeScalarResult(self._items)


class _FakeSession:
    def __init__(self, org=None, execute_items=None):
        self.org = org
        self.execute_items = list(execute_items or [])
        self.added = []
        self.committed = 0
        self.refreshed = []

    async def get(self, model, obj_id):
        return self.org

    async def execute(self, query):
        if self.execute_items:
            items = self.execute_items.pop(0)
        else:
            items = []
        return _FakeResult(items)

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.committed += 1

    async def refresh(self, obj):
        self.refreshed.append(obj)


class _Org:
    def __init__(self, trust_score):
        self.trust_score = trust_score


@pytest.mark.asyncio
async def test_malware_submit_validated_for_trusted_org():
    org_id = uuid.uuid4()
    session = _FakeSession(org=_Org(trust_score=80), execute_items=[[]])
    service = MalwareService(session)
    payload = MalwareCreate(
        name="Example Stealer",
        family=MalwareFamily.stealer,
        description="Example malware sample",
        hash_md5="d41d8cd98f00b204e9800998ecf8427e",
        hash_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        capabilities=["credential theft"],
        tlp="green",
    )

    sample = await service.submit(payload, org_id)

    assert sample.status is MalwareStatus.validated
    assert sample.org_id == org_id
    assert session.committed == 1
    assert session.added and session.added[0].name == payload.name


@pytest.mark.asyncio
async def test_malware_submit_pending_for_low_trust_org():
    org_id = uuid.uuid4()
    session = _FakeSession(org=_Org(trust_score=10), execute_items=[[]])
    service = MalwareService(session)
    payload = MalwareCreate(
        name="Low Trust Sample",
        family=MalwareFamily.rat,
        description="Needs review",
        hash_md5="11111111111111111111111111111111",
        hash_sha256="2222222222222222222222222222222222222222222222222222222222222222",
        capabilities=None,
        tlp="green",
    )

    sample = await service.submit(payload, org_id)

    assert sample.status is MalwareStatus.pending
    assert session.committed == 1


@pytest.mark.asyncio
async def test_malware_submit_rejects_duplicate_hashes():
    org_id = uuid.uuid4()
    session = _FakeSession(org=_Org(trust_score=80), execute_items=[[object()]])
    service = MalwareService(session)
    payload = MalwareCreate(
        name="Duplicate Sample",
        family=MalwareFamily.botnet,
        description="Duplicate",
        hash_md5="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        hash_sha256="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        capabilities=None,
        tlp="green",
    )

    with pytest.raises(HTTPException) as exc_info:
        await service.submit(payload, org_id)

    assert exc_info.value.status_code == 409
    assert session.committed == 0


@pytest.mark.asyncio
async def test_threat_actor_submit_validated_for_trusted_org():
    org_id = uuid.uuid4()
    session = _FakeSession(org=_Org(trust_score=90), execute_items=[[]])
    service = ThreatActorService(session)
    payload = ThreatActorCreate(
        name="Example Threat Actor",
        aliases=["APT-X"],
        motivation=Motivation.espionage,
        country="CN",
        description="Example threat actor",
        tlp="green",
    )

    actor = await service.submit(payload, org_id)

    assert actor.status is ThreatActorStatus.validated
    assert actor.org_id == org_id
    assert session.committed == 1


@pytest.mark.asyncio
async def test_threat_actor_submit_rejects_duplicate_name():
    org_id = uuid.uuid4()
    session = _FakeSession(org=_Org(trust_score=90), execute_items=[[object()]])
    service = ThreatActorService(session)
    payload = ThreatActorCreate(
        name="Existing Actor",
        aliases=None,
        motivation=Motivation.financial,
        country=None,
        description="Duplicate",
        tlp="green",
    )

    with pytest.raises(HTTPException) as exc_info:
        await service.submit(payload, org_id)

    assert exc_info.value.status_code == 409
    assert session.committed == 0


@pytest.mark.asyncio
async def test_list_validated_returns_items():
    session = _FakeSession(execute_items=[["malware-a", "malware-b"], ["actor-a"]])
    malware_service = MalwareService(session)
    threat_actor_service = ThreatActorService(session)

    malware_items = await malware_service.list_validated(limit=2)
    threat_actor_items = await threat_actor_service.list_validated(limit=1)

    assert malware_items == ["malware-a", "malware-b"]
    assert threat_actor_items == ["actor-a"]
