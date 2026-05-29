from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class BlockchainVerificationSummary(BaseModel):
    verified: bool
    current_status: Literal["approved", "false_positive", "no_blockchain_record"]
    latest_tx_hash: str | None
    block_number: int | None
    chain_id: int | None
    contract_address: str | None
    etherscan_url: str | None
    latest_recorded_at: datetime | None
    latest_event_type: str | None
    content_hash: str
    history_length: int

    # Backward-compatible alias some frontend code still checks.
    is_valid: bool


class BlockchainHistoryRecord(BaseModel):
    tx_hash: str
    block_number: int
    event_type: str
    recorded_at: datetime
    etherscan_url: str | None
