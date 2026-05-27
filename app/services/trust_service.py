from __future__ import annotations

from app.models.organisation import Organisation


class TrustService:
    APPROVAL_DELTA = 3
    REJECTION_DELTA = -5
    FALSE_POSITIVE_DELTA = -2
    MIN_SCORE = 0
    MAX_SCORE = 100
    DEFAULT_NEW_ORG_SCORE = 30
    AUTO_APPROVAL_THRESHOLD = 50

    @classmethod
    def clamp(cls, value: int) -> int:
        return max(cls.MIN_SCORE, min(cls.MAX_SCORE, int(value)))

    @classmethod
    def set_score(cls, org: Organisation, score: int) -> int:
        org.trust_score = cls.clamp(score)
        return org.trust_score

    @classmethod
    def apply_delta(cls, org: Organisation, delta: int) -> int:
        org.trust_score = cls.clamp((org.trust_score or 0) + delta)
        return org.trust_score
