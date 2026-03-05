from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import List

from ..http_client import HttpClient
from ..models import ActionArtifact, Finding, Fingerprint, ScanConfig


@dataclass
class CheckContext:
    client: HttpClient
    config: ScanConfig
    fingerprint: Fingerprint


@dataclass
class CheckOutcome:
    findings: List[Finding]
    artifacts: List[ActionArtifact]


class Check(abc.ABC):
    check_id = "BASE"
    name = "base"
    tags: List[str] = []
    profiles: List[str] = ["quick", "standard", "deep", "authenticated-deep"]
    requires_auth: bool = False
    active: bool = False
    # state_changing checks POST/PUT/DELETE data to the target — they require
    # --include-state-changing in addition to --active-tests before they fire.
    state_changing: bool = False

    @abc.abstractmethod
    def run(self, ctx: CheckContext) -> CheckOutcome:
        raise NotImplementedError


def check_selected(check: Check, profile: str, include: List[str], exclude: List[str]) -> bool:
    check_tokens = {check.check_id.lower(), check.name.lower(), *[tag.lower() for tag in check.tags]}
    include_tokens = {item.strip().lower() for item in include if item.strip()}
    exclude_tokens = {item.strip().lower() for item in exclude if item.strip()}

    if profile not in check.profiles:
        return False
    if include_tokens and not check_tokens.intersection(include_tokens):
        return False
    if exclude_tokens and check_tokens.intersection(exclude_tokens):
        return False
    return True
