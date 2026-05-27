from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, status

from app.models.organisation import Organisation
from app.services.trust_service import TrustService


class ModerationService:
    @staticmethod
    def initial_status_for_org(
        org: Organisation,
        *,
        pending_status: Any,
        approved_status: Any,
    ) -> Any:
        if org.trust_score >= TrustService.AUTO_APPROVAL_THRESHOLD:
            return approved_status
        return pending_status

    @staticmethod
    def approve_pending(
        *,
        item: Any,
        org: Organisation,
        pending_status: Any,
        approved_status: Any,
        approved_at_field: str | None = None,
    ) -> None:
        if item.status != pending_status:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Submission is not pending")

        item.status = approved_status
        if approved_at_field:
            setattr(item, approved_at_field, datetime.now(timezone.utc))
        TrustService.apply_delta(org, TrustService.APPROVAL_DELTA)

    @staticmethod
    def reject_pending(
        *,
        item: Any,
        org: Organisation,
        pending_status: Any,
        rejected_status: Any,
        rejected_at_field: str | None = None,
    ) -> None:
        if item.status != pending_status:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Submission is not pending")

        item.status = rejected_status
        if rejected_at_field:
            setattr(item, rejected_at_field, datetime.now(timezone.utc))
        TrustService.apply_delta(org, TrustService.REJECTION_DELTA)

    @staticmethod
    def mark_false_positive(
        *,
        item: Any,
        org: Organisation,
        false_positive_status: Any,
        blocked_statuses: set[Any],
    ) -> None:
        if item.status in blocked_statuses:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Action not available for this status")

        item.status = false_positive_status
        TrustService.apply_delta(org, TrustService.FALSE_POSITIVE_DELTA)
