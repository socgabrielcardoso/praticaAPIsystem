from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IndicatorType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    CVE = "cve"


class Verdict(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class Indicator(BaseModel):
    original: str
    normalized: str
    type: IndicatorType
    public_routable: bool = True


class Finding(BaseModel):
    provider: str
    verdict: Verdict
    score: int = Field(ge=0, le=100)
    confidence: int = Field(default=50, ge=0, le=100)
    summary: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    reference: str | None = None
    checked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ProviderState(BaseModel):
    name: str
    configured: bool
    supported_types: list[IndicatorType]
    reason: str | None = None


class ProviderErrorRecord(BaseModel):
    provider: str
    message: str


class AnalysisResult(BaseModel):
    indicator: Indicator
    verdict: Verdict
    score: int = Field(ge=0, le=100)
    findings: list[Finding] = Field(default_factory=list)
    queried_providers: list[str] = Field(default_factory=list)
    skipped_providers: list[str] = Field(default_factory=list)
    errors: list[ProviderErrorRecord] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    duration_ms: int = Field(ge=0)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AnalyzeRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=2048)


class BatchAnalyzeRequest(BaseModel):
    indicators: list[str] = Field(min_length=1, max_length=100)
