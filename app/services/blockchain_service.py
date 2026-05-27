from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from web3 import Web3
from web3.exceptions import TimeExhausted
from web3.types import TxReceipt

from app.config import settings
from app.models.blockchain_record import BlockchainEventType, BlockchainRecord
from app.models.ioc import IOC


logger = logging.getLogger(__name__)


@dataclass
class BlockchainWriteResult:
    tx_hash: str
    block_number: int
    chain_id: int
    contract_address: str
    block_hash: str | None
    log_index: int | None


class BlockchainService:
    ABI_PATH = Path(__file__).resolve().parents[1] / "blockchain" / "abi" / "threatchain_ioc_verifier.json"

    _EVENT_TYPE_TO_CONTRACT_VALUE = {
        BlockchainEventType.IOC_APPROVED: 0,
        BlockchainEventType.IOC_FALSE_POSITIVE: 1,
    }

    def __init__(self, db: AsyncSession):
        self.db = db

    @classmethod
    def _load_abi(cls) -> list[dict[str, Any]]:
        with cls.ABI_PATH.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        if not isinstance(loaded, list):
            raise ValueError("Contract ABI must be a JSON array")
        return loaded

    @staticmethod
    def _normalize_text(value: str | None, *, lowercase: bool = False) -> str:
        text = (value or "").strip()
        return text.lower() if lowercase else text

    @staticmethod
    def _normalize_datetime(value: datetime | None) -> str:
        if value is None:
            return ""
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @classmethod
    def build_canonical_ioc_payload(cls, ioc: IOC) -> dict[str, Any]:
        tags = sorted({tag.strip() for tag in (ioc.tags or []) if isinstance(tag, str) and tag.strip()})
        ioc_type = ioc.type.value if hasattr(ioc.type, "value") else str(ioc.type)
        return {
            "id": str(ioc.id),
            "type": cls._normalize_text(ioc_type, lowercase=True),
            "value": cls._normalize_text(ioc.value),
            "description": cls._normalize_text(ioc.description),
            "org_id": str(ioc.org_id),
            "tlp": cls._normalize_text(ioc.tlp, lowercase=True),
            "confidence": int(ioc.confidence or 0),
            "first_seen": cls._normalize_datetime(ioc.first_seen),
            "last_seen": cls._normalize_datetime(ioc.last_seen),
            "tags": tags,
            "source_context": cls._normalize_text(ioc.source_context),
        }

    @classmethod
    def compute_ioc_content_hash_bytes32(cls, ioc: IOC) -> bytes:
        canonical_payload = cls.build_canonical_ioc_payload(ioc)
        serialized = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(serialized.encode("utf-8")).digest()

    @staticmethod
    def ioc_uuid_to_bytes32(ioc_id: uuid.UUID) -> bytes:
        # Preserve raw UUID bytes and right-pad to bytes32 for deterministic mapping.
        return ioc_id.bytes + (b"\x00" * 16)

    @staticmethod
    def _is_configured() -> bool:
        return bool(
            settings.ETH_RPC_URL
            and settings.ETH_PRIVATE_KEY
            and settings.ETH_CONTRACT_ADDRESS
        )

    def _submit_ioc_event_tx_sync(
        self,
        *,
        ioc_id: uuid.UUID,
        event_type: BlockchainEventType,
        content_hash: bytes,
    ) -> BlockchainWriteResult:
        if not self._is_configured():
            raise RuntimeError("Blockchain settings are incomplete")

        w3 = Web3(Web3.HTTPProvider(settings.ETH_RPC_URL, request_kwargs={"timeout": 30}))
        if not w3.is_connected():
            raise RuntimeError("Unable to connect to ETH_RPC_URL")

        abi = self._load_abi()
        contract_address = Web3.to_checksum_address(settings.ETH_CONTRACT_ADDRESS)
        account = w3.eth.account.from_key(settings.ETH_PRIVATE_KEY)
        chain_id = int(settings.ETH_CHAIN_ID or w3.eth.chain_id)
        network_chain_id = int(w3.eth.chain_id)
        if chain_id != network_chain_id:
            raise RuntimeError(
                f"Configured chain id {chain_id} does not match RPC chain id {network_chain_id}"
            )

        contract = w3.eth.contract(address=contract_address, abi=abi)
        ioc_id_bytes32 = self.ioc_uuid_to_bytes32(ioc_id)
        event_value = self._EVENT_TYPE_TO_CONTRACT_VALUE[event_type]

        tx = contract.functions.recordIOCEvent(ioc_id_bytes32, event_value, content_hash).build_transaction(
            {
                "from": account.address,
                "nonce": w3.eth.get_transaction_count(account.address),
                "chainId": chain_id,
            }
        )
        signed_tx = w3.eth.account.sign_transaction(tx, private_key=settings.ETH_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        try:
            receipt: TxReceipt = w3.eth.wait_for_transaction_receipt(
                tx_hash,
                timeout=settings.ETH_TX_TIMEOUT_SECONDS,
            )
        except TimeExhausted as exc:
            raise RuntimeError("Timed out while waiting for blockchain transaction receipt") from exc
        if int(receipt.get("status", 0)) != 1:
            raise RuntimeError("Blockchain transaction reverted")

        log_index: int | None = None
        try:
            decoded_logs = contract.events.IOCEventRecorded().process_receipt(receipt)
            if decoded_logs:
                log_index = int(decoded_logs[0].get("logIndex"))
        except Exception:
            logger.exception("Failed to decode IOCEventRecorded logs", extra={"tx_hash": tx_hash.hex()})
            for raw_log in receipt.get("logs", []):
                if str(raw_log.get("address", "")).lower() == contract_address.lower():
                    log_index = int(raw_log.get("logIndex"))
                    break

        block_hash_hex: str | None = None
        if receipt.get("blockHash") is not None:
            block_hash_hex = receipt["blockHash"].hex()

        return BlockchainWriteResult(
            tx_hash=tx_hash.hex(),
            block_number=int(receipt["blockNumber"]),
            chain_id=chain_id,
            contract_address=contract_address,
            block_hash=block_hash_hex,
            log_index=log_index,
        )

    async def record_ioc_event(self, *, ioc: IOC, event_type: BlockchainEventType) -> BlockchainRecord | None:
        if not self._is_configured():
            logger.info(
                "Blockchain integration skipped because ETH settings are incomplete",
                extra={"ioc_id": str(ioc.id), "event_type": event_type.value},
            )
            return None

        content_hash = self.compute_ioc_content_hash_bytes32(ioc)
        try:
            write_result = await asyncio.to_thread(
                self._submit_ioc_event_tx_sync,
                ioc_id=ioc.id,
                event_type=event_type,
                content_hash=content_hash,
            )
        except Exception:
            logger.exception(
                "Blockchain transaction failed for IOC event",
                extra={"ioc_id": str(ioc.id), "event_type": event_type.value},
            )
            return None

        record = BlockchainRecord(
            ioc_id=ioc.id,
            event_type=event_type,
            tx_hash=write_result.tx_hash,
            block_number=write_result.block_number,
            chain_id=write_result.chain_id,
            contract_address=write_result.contract_address,
            block_hash=write_result.block_hash,
            log_index=write_result.log_index,
        )
        self.db.add(record)
        try:
            await self.db.commit()
        except Exception:
            await self.db.rollback()
            logger.exception(
                "Failed to persist blockchain record",
                extra={"ioc_id": str(ioc.id), "event_type": event_type.value, "tx_hash": write_result.tx_hash},
            )
            return None

        return record
