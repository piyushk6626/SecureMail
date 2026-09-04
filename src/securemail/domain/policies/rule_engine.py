"""Pure policy-pack evaluator. Thresholds and applicability live in YAML data."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Any, Literal, NamedTuple

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from securemail.domain.evidence.certificate import CertificateEvidence, CertificateRole
from securemail.domain.evidence.flow import Flow
from securemail.domain.evidence.handshake import TlsHandshake
from securemail.domain.evidence.run import EvidenceState, PolicyProfile
from securemail.domain.evidence.session import EmailSession
from securemail.domain.findings.finding import (
    EvidenceRecordType,
    EvidenceReference,
    Finding,
    FindingOutcome,
    FindingSeverity,
)
from securemail.domain.findings.posture import (
    CheckCategory,
    CoverageProtocol,
    PolicyCheck,
    PolicyCheckOutcome,
)
from securemail.domain.policies.tls.forward_secrecy import assess_forward_secrecy

_UNUSABLE_STATES = frozenset(
    {
        EvidenceState.INCOMPLETE,
        EvidenceState.CONFLICTING,
        EvidenceState.NOT_OBSERVABLE,
        EvidenceState.INDETERMINATE,
    }
)
_STATE_RANK = {
    EvidenceState.CONFLICTING: 0,
    EvidenceState.INCOMPLETE: 1,
    EvidenceState.INDETERMINATE: 2,
    EvidenceState.NOT_OBSERVABLE: 3,
    EvidenceState.INFERRED: 4,
    EvidenceState.OBSERVED: 5,
    EvidenceState.VERIFIED: 6,
}
_TARGET_RANK = {
    "flow": 0,
    "session": 1,
    "handshake": 2,
    "certificate": 3,
}
_CHECK_CATEGORY = {
    "flow": CheckCategory.TRANSPORT,
    "session": CheckCategory.MAIL_PROTOCOL,
    "handshake": CheckCategory.TLS_HANDSHAKE,
    "certificate": CheckCategory.CERTIFICATE,
}
_UNKNOWN_COVERAGE_STATES = frozenset(
    {
        EvidenceState.INCOMPLETE,
        EvidenceState.CONFLICTING,
        EvidenceState.INDETERMINATE,
    }
)
_MAX_RULES = 128
_MAX_ROLES = 16
_MAX_PREDICATES = 16
_MAX_TESTS = 8
_MAX_COLLECTION = 64
_MAX_PATH_DEPTH = 8
_MAX_PATH_LEN = 160
_MAX_ID_LEN = 64
_MAX_TITLE_LEN = 160
_MAX_RATIONALE_LEN = 1000
_MAX_STANDARDS = 8

ALLOWED_PATHS: frozenset[str] = frozenset(
    {
        "flow.uid",
        "flow.resp.host",
        "flow.resp.port",
        "flow.orig.host",
        "flow.orig.port",
        "flow.evidence_state",
        "session.uid",
        "session.protocol",
        "session.evidence_state",
        "session.explicit_upgrade.state",
        "session.explicit_upgrade.evidence_state",
        "session.implicit_tls.correlated_protocol",
        "session.implicit_tls.evidence_state",
        "handshake.uid",
        "handshake.established",
        "handshake.resumed",
        "handshake.evidence_state",
        "handshake.visibility",
        "handshake.version.selected",
        "handshake.version.evidence_state",
        "handshake.cipher_suite.name",
        "handshake.cipher_suite.code",
        "handshake.cipher_suite.evidence_state",
        "handshake.key_exchange.mechanism",
        "handshake.key_exchange.evidence_state",
        "handshake.key_exchange.dh_param_size",
        "handshake.certificate_verify_signature.algorithm",
        "handshake.certificate_verify_signature.evidence_state",
        "certificate.uid",
        "certificate.chain_index",
        "certificate.role",
        "certificate.der_sha256",
        "certificate.evidence_state",
        "certificate.public_key_algorithm",
        "certificate.public_key_size",
        "certificate.public_key_curve",
        "certificate.effective_strength_bits",
        "certificate.signature_algorithm",
        "certificate.valid_at_capture_time",
        "certificate.valid_at_analysis_time",
        "certificate.validation.path_valid_at_capture_time",
        "certificate.validation.path_valid_at_analysis_time",
        "certificate.validation.identity_match",
        "derived.service_role",
        "derived.forward_secrecy.outcome",
        "derived.forward_secrecy.evidence_state",
        "derived.observed_commands",
        "derived.transport_tls_established",
    }
)


PolicyRecord = Flow | EmailSession | TlsHandshake | CertificateEvidence


class PolicyEngineError(ValueError):
    """Raised when a rule pack or evaluation context is invalid."""


class PolicyOperator(StrEnum):
    EQ = "eq"
    NOT_EQ = "not_eq"
    IN = "in"
    NOT_IN = "not_in"
    LT = "lt"
    LTE = "lte"
    GT = "gt"
    GTE = "gte"
    CONTAINS_ANY = "contains_any"
    CONTAINS_NONE = "contains_none"


class PolicyTarget(StrEnum):
    HANDSHAKE = "handshake"
    SESSION = "session"
    CERTIFICATE = "certificate"
    FLOW = "flow"


class EvaluationClock(StrEnum):
    ANALYSIS_TIME = "analysis_time"
    CAPTURE_START_TIME = "capture_start_time"


class PredicateTriState(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    UNUSABLE = "unusable"


class RuleEvalResult(StrEnum):
    PASS = "pass"
    NEGATIVE = "negative"
    INDETERMINATE = "indeterminate"
    NOT_APPLICABLE = "not_applicable"


class Predicate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=_MAX_PATH_LEN)
    operator: PolicyOperator
    value: Any
    state_path: str | None = Field(default=None, max_length=_MAX_PATH_LEN)

    @field_validator("path", "state_path")
    @classmethod
    def _known_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if value.count(".") + 1 > _MAX_PATH_DEPTH:
            raise ValueError(f"policy path exceeds depth bound: {value}")
        if value not in ALLOWED_PATHS:
            raise ValueError(f"unknown policy path: {value}")
        return value

    @field_validator("value")
    @classmethod
    def _bounded_value(cls, value: Any) -> Any:
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, float):
            raise ValueError("policy thresholds must not be floats")
        if isinstance(value, str) and len(value) > 160:
            raise ValueError("policy string value is too long")
        if isinstance(value, list):
            if len(value) > _MAX_COLLECTION:
                raise ValueError("policy collection exceeds the configured bound")
            for item in value:
                if isinstance(item, float) or isinstance(item, bool):
                    raise ValueError("policy collection values must be strings or integers")
                if isinstance(item, str) and len(item) > 160:
                    raise ValueError("policy collection value is too long")
                if not isinstance(item, (str, int)):
                    raise ValueError("policy collection values must be strings or integers")
        return value


class RoleDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=_MAX_ID_LEN)
    all: list[Predicate] = Field(min_length=1, max_length=_MAX_PREDICATES)


class RuleSeverity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    negative: FindingSeverity
    indeterminate: FindingSeverity = FindingSeverity.INFORMATIONAL


class InlineRuleTest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=_MAX_ID_LEN)
    at: date
    values: dict[str, Any] = Field(min_length=1)
    expected: Literal["pass", "negative", "indeterminate"]

    @field_validator("values")
    @classmethod
    def _known_value_paths(cls, values: dict[str, Any]) -> dict[str, Any]:
        if len(values) > 32:
            raise ValueError("inline test values exceed the configured bound")
        for path in values:
            if path not in ALLOWED_PATHS:
                raise ValueError(f"unknown policy path in inline test: {path}")
        return values


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=_MAX_ID_LEN)
    target: PolicyTarget
    effective_from: date
    effective_until: date | None = None
    roles: list[str] = Field(default_factory=list, max_length=_MAX_ROLES)
    where: list[Predicate] = Field(default_factory=list, max_length=_MAX_PREDICATES)
    assertion: list[Predicate] = Field(min_length=1, max_length=_MAX_PREDICATES)
    fail_outcome: FindingOutcome = FindingOutcome.NEGATIVE
    severity: RuleSeverity
    title: str = Field(min_length=1, max_length=_MAX_TITLE_LEN)
    rationale: str = Field(min_length=1, max_length=_MAX_RATIONALE_LEN)
    standards: list[str] = Field(min_length=1, max_length=_MAX_STANDARDS)
    remediation_id: str = Field(min_length=1, max_length=_MAX_ID_LEN)
    tests: list[InlineRuleTest] = Field(min_length=1, max_length=_MAX_TESTS)

    @model_validator(mode="after")
    def _interval(self) -> PolicyRule:
        if self.effective_until is not None and self.effective_until <= self.effective_from:
            raise ValueError(f"rule {self.id} has an empty effective interval")
        return self


class PolicyPack(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["securemail.policy/v1"]
    profile: PolicyProfile
    version: str = Field(min_length=1, max_length=32)
    evaluation_clock: EvaluationClock
    roles: list[RoleDefinition] = Field(default_factory=list, max_length=_MAX_ROLES)
    rules: list[PolicyRule] = Field(min_length=1, max_length=_MAX_RULES)

    @model_validator(mode="after")
    def _unique_ids(self) -> PolicyPack:
        role_ids = [role.id for role in self.roles]
        if len(role_ids) != len(set(role_ids)):
            raise ValueError("rule pack has duplicate role ids")
        rule_ids = [rule.id for rule in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("rule pack has duplicate rule ids")
        known_roles = set(role_ids)
        for rule in self.rules:
            for role in rule.roles:
                if role not in known_roles:
                    raise ValueError(f"rule {rule.id} references unknown role {role}")
        tests = sum(len(rule.tests) for rule in self.rules)
        if tests > 512:
            raise ValueError("rule pack exceeds the inline-test bound")
        return self


def canonical_pack_digest(pack: PolicyPack) -> str:
    """SHA-256 of canonical JSON. Not a digital signature."""

    payload = pack.model_dump(mode="json")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def resolve_evaluation_clock(
    pack: PolicyPack,
    *,
    analysis_time: datetime,
    capture_start_time: datetime | None,
) -> datetime:
    if pack.evaluation_clock is EvaluationClock.ANALYSIS_TIME:
        return _as_utc(analysis_time)
    if capture_start_time is None:
        raise PolicyEngineError(
            "capture start time unavailable; historical policy cannot be evaluated"
        )
    return _as_utc(capture_start_time)


class PolicyEvaluation(BaseModel):
    """Findings plus applicable coverage observations for one pack evaluation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    findings: list[Finding]
    checks: list[PolicyCheck]


class _RuleCoverage(NamedTuple):
    result: RuleEvalResult
    check_outcome: PolicyCheckOutcome | None
    coverage_state: EvidenceState | None


def evaluate_inline_test(rule: PolicyRule, test: InlineRuleTest) -> RuleEvalResult:
    """Evaluate one YAML inline case against a synthetic context."""

    instant = datetime(test.at.year, test.at.month, test.at.day, tzinfo=UTC)
    if not _rule_active(rule, instant):
        return RuleEvalResult.NOT_APPLICABLE
    context = _context_from_values(test.values)
    return _evaluate_rule_on_context(rule, context, instant)


def evaluate_policy(
    *,
    pack: PolicyPack,
    pack_digest: str,
    capture_sha256: str,
    evaluation_time: datetime,
    flows: Sequence[Flow],
    sessions: Sequence[EmailSession],
    handshakes: Sequence[TlsHandshake],
    certificates: Sequence[CertificateEvidence],
) -> list[Finding]:
    """Apply a typed rule pack to canonical evidence. Never mutates inputs."""

    return evaluate_policy_batch(
        pack=pack,
        pack_digest=pack_digest,
        capture_sha256=capture_sha256,
        evaluation_time=evaluation_time,
        flows=flows,
        sessions=sessions,
        handshakes=handshakes,
        certificates=certificates,
    ).findings


def evaluate_policy_batch(
    *,
    pack: PolicyPack,
    pack_digest: str,
    capture_sha256: str,
    evaluation_time: datetime,
    flows: Sequence[Flow],
    sessions: Sequence[EmailSession],
    handshakes: Sequence[TlsHandshake],
    certificates: Sequence[CertificateEvidence],
) -> PolicyEvaluation:
    """Evaluate a pack and retain applicable pass/fail/unknown/not-observable checks."""

    instant = _as_utc(evaluation_time)
    flow_by_uid = {flow.uid: flow for flow in flows}
    session_by_uid = {session.uid: session for session in sessions}
    handshake_by_uid: dict[str, TlsHandshake] = {}
    for handshake in handshakes:
        handshake_by_uid.setdefault(handshake.uid, handshake)
    certs_by_uid: dict[str, list[CertificateEvidence]] = {}
    for certificate in certificates:
        certs_by_uid.setdefault(certificate.uid, []).append(certificate)

    findings: list[Finding] = []
    checks: list[PolicyCheck] = []
    for rule in pack.rules:
        if not _rule_active(rule, instant):
            continue
        records = _records_for_target(
            rule.target,
            flows=flows,
            sessions=sessions,
            handshakes=handshakes,
            certificates=certificates,
        )
        for record in records:
            context = _build_context(
                record,
                rule.target,
                pack=pack,
                flow_by_uid=flow_by_uid,
                session_by_uid=session_by_uid,
                handshake_by_uid=handshake_by_uid,
                certs_by_uid=certs_by_uid,
            )
            coverage = _evaluate_rule_with_coverage(rule, context, instant)
            if coverage.check_outcome is not None and coverage.coverage_state is not None:
                checks.append(
                    _to_check(
                        rule=rule,
                        pack=pack,
                        pack_digest=pack_digest,
                        capture_sha256=capture_sha256,
                        context=context,
                        record=record,
                        target=rule.target,
                        check_outcome=coverage.check_outcome,
                        coverage_state=coverage.coverage_state,
                    )
                )
            if (
                coverage.result is RuleEvalResult.PASS
                or coverage.result is RuleEvalResult.NOT_APPLICABLE
            ):
                continue
            outcome = (
                FindingOutcome.INDETERMINATE
                if coverage.result is RuleEvalResult.INDETERMINATE
                else rule.fail_outcome
            )
            if coverage.result is RuleEvalResult.NEGATIVE:
                outcome = rule.fail_outcome
            findings.append(
                _to_finding(
                    rule=rule,
                    pack=pack,
                    pack_digest=pack_digest,
                    capture_sha256=capture_sha256,
                    evaluation_time=instant,
                    context=context,
                    outcome=outcome,
                    record=record,
                    target=rule.target,
                )
            )
    findings.sort(
        key=lambda item: (
            item.affected_endpoint,
            _TARGET_RANK.get(item.evidence_references[0].record_type.value, 9)
            if item.evidence_references
            else 9,
            item.evidence_references[0].record_key if item.evidence_references else "",
            item.code,
            item.outcome.value,
        )
    )
    checks.sort(
        key=lambda item: (
            item.affected_endpoint,
            item.category.value,
            item.record_key,
            item.code,
            item.outcome.value,
        )
    )
    return PolicyEvaluation(findings=findings, checks=checks)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _rule_active(rule: PolicyRule, instant: datetime) -> bool:
    day = instant.date()
    if day < rule.effective_from:
        return False
    if rule.effective_until is not None and day >= rule.effective_until:
        return False
    return True


def _records_for_target(
    target: PolicyTarget,
    *,
    flows: Sequence[Flow],
    sessions: Sequence[EmailSession],
    handshakes: Sequence[TlsHandshake],
    certificates: Sequence[CertificateEvidence],
) -> Sequence[PolicyRecord]:
    if target is PolicyTarget.HANDSHAKE:
        return handshakes
    if target is PolicyTarget.SESSION:
        return sessions
    if target is PolicyTarget.CERTIFICATE:
        return certificates
    return flows


def _build_context(
    record: PolicyRecord,
    target: PolicyTarget,
    *,
    pack: PolicyPack,
    flow_by_uid: Mapping[str, Flow],
    session_by_uid: Mapping[str, EmailSession],
    handshake_by_uid: Mapping[str, TlsHandshake],
    certs_by_uid: Mapping[str, list[CertificateEvidence]],
) -> dict[str, object]:
    uid = record.uid
    flow = flow_by_uid.get(uid)
    session = session_by_uid.get(uid)
    handshake = record if target is PolicyTarget.HANDSHAKE else handshake_by_uid.get(uid)
    certificate: CertificateEvidence | None
    if target is PolicyTarget.CERTIFICATE:
        certificate = record if isinstance(record, CertificateEvidence) else None
    else:
        certificate = _leaf_certificate(certs_by_uid.get(uid, ()))
    derived = _derived(
        pack=pack,
        flow=flow,
        session=session,
        handshake=handshake if isinstance(handshake, TlsHandshake) else None,
    )
    return {
        "flow": None if flow is None else flow.model_dump(mode="json"),
        "session": None if session is None else session.model_dump(mode="json"),
        "handshake": None
        if not isinstance(handshake, TlsHandshake)
        else handshake.model_dump(mode="json"),
        "certificate": None if certificate is None else certificate.model_dump(mode="json"),
        "derived": derived,
    }


def _leaf_certificate(certificates: Sequence[CertificateEvidence]) -> CertificateEvidence | None:
    leaves = [
        item
        for item in certificates
        if item.chain_index == 0 and item.role is CertificateRole.SERVER
    ]
    if not leaves:
        return None
    return sorted(leaves, key=lambda item: item.der_sha256)[0]


def _derived(
    *,
    pack: PolicyPack,
    flow: Flow | None,
    session: EmailSession | None,
    handshake: TlsHandshake | None,
) -> dict[str, object]:
    fs = None if handshake is None else assess_forward_secrecy(handshake)
    commands: list[str] = []
    if session is not None:
        for event in session.events:
            if event.command:
                commands.append(event.command.upper())
    tls_established = False
    if handshake is not None and handshake.established:
        tls_established = True
    if session is not None and session.explicit_upgrade is not None:
        if session.explicit_upgrade.state is not None and session.explicit_upgrade.state.value == (
            "tls_established"
        ):
            tls_established = True
    return {
        "service_role": _service_role(pack, flow, session),
        "forward_secrecy": None
        if fs is None
        else {
            "outcome": fs.outcome.value,
            "evidence_state": fs.evidence_state.value,
        },
        "observed_commands": commands,
        "transport_tls_established": tls_established,
    }


def _service_role(pack: PolicyPack, flow: Flow | None, session: EmailSession | None) -> str:
    if session is None or flow is None:
        return "unclassified"
    context: dict[str, object] = {
        "flow": flow.model_dump(mode="json"),
        "session": session.model_dump(mode="json"),
        "handshake": None,
        "certificate": None,
        "derived": {},
    }
    matches: list[str] = []
    for role in pack.roles:
        state = _eval_predicates(role.all, context)
        if state is PredicateTriState.PASS:
            matches.append(role.id)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        return "indeterminate"
    return "unclassified"


def _evaluate_rule_on_context(
    rule: PolicyRule,
    context: Mapping[str, object],
    instant: datetime,
) -> RuleEvalResult:
    return _evaluate_rule_with_coverage(rule, context, instant).result


def _evaluate_rule_with_coverage(
    rule: PolicyRule,
    context: Mapping[str, object],
    instant: datetime,
) -> _RuleCoverage:
    if not _rule_active(rule, instant):
        return _RuleCoverage(RuleEvalResult.NOT_APPLICABLE, None, None)
    if rule.roles:
        role = _get_path(context, "derived.service_role")
        if not isinstance(role, str) or role not in rule.roles:
            return _RuleCoverage(RuleEvalResult.NOT_APPLICABLE, None, None)
    where_state, where_unusable = _eval_predicates_with_unusable(rule.where, context)
    if where_state is PredicateTriState.FAIL:
        return _RuleCoverage(RuleEvalResult.NOT_APPLICABLE, None, None)
    if where_state is PredicateTriState.UNUSABLE:
        outcome, state = _coverage_from_unusable(where_unusable)
        return _RuleCoverage(RuleEvalResult.NOT_APPLICABLE, outcome, state)
    assertion_state, assertion_unusable = _eval_predicates_with_unusable(rule.assertion, context)
    assertion_states = _predicate_states(rule.assertion, context)
    if assertion_state is PredicateTriState.PASS:
        return _RuleCoverage(
            RuleEvalResult.PASS,
            PolicyCheckOutcome.PASS,
            _weakest_or_observed(assertion_states),
        )
    if assertion_state is PredicateTriState.UNUSABLE:
        outcome, state = _coverage_from_unusable(assertion_unusable)
        return _RuleCoverage(RuleEvalResult.INDETERMINATE, outcome, state)
    if rule.fail_outcome is FindingOutcome.INDETERMINATE:
        return _RuleCoverage(
            RuleEvalResult.INDETERMINATE,
            PolicyCheckOutcome.UNKNOWN,
            _weakest_or_observed(assertion_states),
        )
    return _RuleCoverage(
        RuleEvalResult.NEGATIVE,
        PolicyCheckOutcome.FAIL,
        _weakest_or_observed(assertion_states),
    )


def _coverage_from_unusable(
    states: Sequence[EvidenceState],
) -> tuple[PolicyCheckOutcome, EvidenceState]:
    if not states:
        return PolicyCheckOutcome.UNKNOWN, EvidenceState.INDETERMINATE
    weakest = min(states, key=lambda item: _STATE_RANK[item])
    if weakest in _UNKNOWN_COVERAGE_STATES:
        return PolicyCheckOutcome.UNKNOWN, weakest
    if weakest is EvidenceState.NOT_OBSERVABLE:
        return PolicyCheckOutcome.NOT_OBSERVABLE, weakest
    return PolicyCheckOutcome.UNKNOWN, weakest


def _weakest_or_observed(states: Sequence[EvidenceState]) -> EvidenceState:
    if not states:
        return EvidenceState.OBSERVED
    return min(states, key=lambda item: _STATE_RANK[item])


def _eval_predicates(
    predicates: Sequence[Predicate],
    context: Mapping[str, object],
) -> PredicateTriState:
    return _eval_predicates_with_unusable(predicates, context)[0]


def _eval_predicates_with_unusable(
    predicates: Sequence[Predicate],
    context: Mapping[str, object],
) -> tuple[PredicateTriState, list[EvidenceState]]:
    if not predicates:
        return PredicateTriState.PASS, []
    saw_unusable = False
    unusable_states: list[EvidenceState] = []
    for predicate in predicates:
        state = _eval_predicate(predicate, context)
        if state is PredicateTriState.FAIL:
            return PredicateTriState.FAIL, []
        if state is PredicateTriState.UNUSABLE:
            saw_unusable = True
            unusable_states.append(_evidence_state_for_predicate(predicate, context))
    if saw_unusable:
        return PredicateTriState.UNUSABLE, unusable_states
    return PredicateTriState.PASS, []


def _predicate_states(
    predicates: Sequence[Predicate],
    context: Mapping[str, object],
) -> list[EvidenceState]:
    return [_evidence_state_for_predicate(item, context) for item in predicates]


def _eval_predicate(predicate: Predicate, context: Mapping[str, object]) -> PredicateTriState:
    if predicate.state_path is not None:
        raw_state = _get_path(context, predicate.state_path)
        if isinstance(raw_state, str) and raw_state in {item.value for item in _UNUSABLE_STATES}:
            return PredicateTriState.UNUSABLE
    actual = _get_path(context, predicate.path)
    if actual is None:
        return PredicateTriState.UNUSABLE
    try:
        matched = _compare(predicate.operator, actual, predicate.value)
    except PolicyEngineError:
        return PredicateTriState.UNUSABLE
    return PredicateTriState.PASS if matched else PredicateTriState.FAIL


def _compare(operator: PolicyOperator, actual: object, expected: object) -> bool:
    if operator is PolicyOperator.EQ:
        return _normalize(actual) == _normalize(expected)
    if operator is PolicyOperator.NOT_EQ:
        return _normalize(actual) != _normalize(expected)
    if operator is PolicyOperator.IN:
        if not isinstance(expected, list):
            raise PolicyEngineError("in requires a list")
        return _normalize(actual) in {_normalize(item) for item in expected}
    if operator is PolicyOperator.NOT_IN:
        if not isinstance(expected, list):
            raise PolicyEngineError("not_in requires a list")
        return _normalize(actual) not in {_normalize(item) for item in expected}
    if operator in {
        PolicyOperator.LT,
        PolicyOperator.LTE,
        PolicyOperator.GT,
        PolicyOperator.GTE,
    }:
        if not isinstance(actual, int) or isinstance(actual, bool):
            raise PolicyEngineError("numeric comparison requires an integer")
        if not isinstance(expected, int) or isinstance(expected, bool):
            raise PolicyEngineError("numeric comparison requires an integer threshold")
        if operator is PolicyOperator.LT:
            return actual < expected
        if operator is PolicyOperator.LTE:
            return actual <= expected
        if operator is PolicyOperator.GT:
            return actual > expected
        return actual >= expected
    if operator is PolicyOperator.CONTAINS_ANY:
        if not isinstance(expected, list):
            raise PolicyEngineError("contains_any requires a list")
        return _contains_any(actual, expected)
    if operator is PolicyOperator.CONTAINS_NONE:
        if not isinstance(expected, list):
            raise PolicyEngineError("contains_none requires a list")
        return not _contains_any(actual, expected)
    raise PolicyEngineError(f"unsupported operator: {operator}")


def _contains_any(actual: object, needles: list[object]) -> bool:
    if isinstance(actual, str):
        haystack = actual.lower()
        return any(isinstance(item, str) and item.lower() in haystack for item in needles)
    if isinstance(actual, list):
        normalized = {_normalize(item) for item in actual}
        return any(_normalize(item) in normalized for item in needles)
    return False


def _normalize(value: object) -> object:
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    return value


def _get_path(context: Mapping[str, object], path: str) -> object:
    current: object = context
    for part in path.split("."):
        if current is None:
            return None
        if isinstance(current, Mapping):
            current = current.get(part)
            continue
        return None
    return current


def _context_from_values(values: Mapping[str, object]) -> dict[str, object]:
    root: dict[str, object] = {
        "derived": {
            "service_role": "unclassified",
            "observed_commands": [],
            "transport_tls_established": False,
        }
    }
    for path, value in values.items():
        parts = path.split(".")
        cursor: dict[str, object] = root
        for part in parts[:-1]:
            existing = cursor.get(part)
            if not isinstance(existing, dict):
                existing = {}
                cursor[part] = existing
            cursor = existing
        cursor[parts[-1]] = value
    return root


def _to_finding(
    *,
    rule: PolicyRule,
    pack: PolicyPack,
    pack_digest: str,
    capture_sha256: str,
    evaluation_time: datetime,
    context: Mapping[str, object],
    outcome: FindingOutcome,
    record: PolicyRecord,
    target: PolicyTarget,
) -> Finding:
    record_key = _record_key(record, target)
    references = _references(rule, context, record_key, target)
    basis = _weakest_state(references)
    evaluation_state = (
        EvidenceState.INDETERMINATE
        if outcome is FindingOutcome.INDETERMINATE
        else EvidenceState.VERIFIED
    )
    endpoint = _endpoint_from_context(context)
    severity = (
        rule.severity.indeterminate
        if outcome is FindingOutcome.INDETERMINATE
        else rule.severity.negative
    )
    finding_id = hashlib.sha256(
        "|".join(
            [
                capture_sha256,
                pack.profile.value,
                pack_digest,
                rule.id,
                outcome.value,
                target.value,
                record_key,
            ]
        ).encode("utf-8")
    ).hexdigest()
    return Finding(
        finding_id=finding_id,
        code=rule.id,
        outcome=outcome,
        title=rule.title,
        rationale=rule.rationale,
        standards=list(rule.standards),
        remediation_id=rule.remediation_id,
        severity=severity,
        evaluation_state=evaluation_state,
        basis_state=basis,
        policy_profile=pack.profile.value,
        policy_pack_version=pack_digest,
        rule_effective_from=rule.effective_from,
        rule_effective_until=rule.effective_until,
        policy_evaluation_time=evaluation_time,
        affected_endpoint=endpoint,
        evidence_references=references,
    )


def _record_key(record: PolicyRecord, target: PolicyTarget) -> str:
    uid = record.uid
    if target is PolicyTarget.CERTIFICATE and isinstance(record, CertificateEvidence):
        return f"{uid}:{record.role.value}:{record.chain_index}:{record.der_sha256}"
    return uid


def _references(
    rule: PolicyRule,
    context: Mapping[str, object],
    record_key: str,
    target: PolicyTarget,
) -> list[EvidenceReference]:
    pairs: list[tuple[str, EvidenceState]] = []
    for predicate in (*rule.where, *rule.assertion):
        pairs.append((predicate.path, _evidence_state_for_predicate(predicate, context)))
    if rule.roles:
        pairs.append(("derived.service_role", EvidenceState.INFERRED))
    unique: dict[str, EvidenceState] = {}
    order: list[str] = []
    for path, state in pairs:
        if path not in unique:
            unique[path] = state
            order.append(path)
            continue
        if _STATE_RANK[state] < _STATE_RANK[unique[path]]:
            unique[path] = state
    record_type = EvidenceRecordType(target.value)
    refs = [
        EvidenceReference(
            record_type=record_type,
            record_key=record_key,
            field_path=path,
            evidence_state=unique[path],
        )
        for path in order
    ]
    refs.sort(key=lambda item: (item.record_type.value, item.record_key, item.field_path))
    return refs


def _evidence_state_for_predicate(
    predicate: Predicate, context: Mapping[str, object]
) -> EvidenceState:
    source = predicate.state_path or predicate.path
    state = _state_for_path(context, source)
    actual = _get_path(context, predicate.path)
    if actual is None and state in {
        EvidenceState.OBSERVED,
        EvidenceState.VERIFIED,
        EvidenceState.INFERRED,
    }:
        return EvidenceState.INDETERMINATE
    return state


def _state_for_path(context: Mapping[str, object], path: str) -> EvidenceState:
    if path.endswith("evidence_state"):
        raw = _get_path(context, path)
        if isinstance(raw, str):
            try:
                return EvidenceState(raw)
            except ValueError:
                return EvidenceState.INDETERMINATE
    parent = path.rsplit(".", 1)[0]
    sibling = _get_path(context, f"{parent}.evidence_state")
    if isinstance(sibling, str):
        try:
            return EvidenceState(sibling)
        except ValueError:
            return EvidenceState.INDETERMINATE
    root = path.split(".", 1)[0]
    root_state = _get_path(context, f"{root}.evidence_state")
    if isinstance(root_state, str):
        try:
            return EvidenceState(root_state)
        except ValueError:
            return EvidenceState.INDETERMINATE
    if path.startswith("derived."):
        return EvidenceState.INFERRED
    return EvidenceState.OBSERVED


def _protocol_from_context(context: Mapping[str, object]) -> CoverageProtocol:
    session = context.get("session")
    if isinstance(session, Mapping):
        protocol = session.get("protocol")
        if protocol in {
            CoverageProtocol.SMTP.value,
            CoverageProtocol.IMAP.value,
            CoverageProtocol.POP3.value,
        }:
            return CoverageProtocol(protocol)
    return CoverageProtocol.UNCLASSIFIED


def _to_check(
    *,
    rule: PolicyRule,
    pack: PolicyPack,
    pack_digest: str,
    capture_sha256: str,
    context: Mapping[str, object],
    record: PolicyRecord,
    target: PolicyTarget,
    check_outcome: PolicyCheckOutcome,
    coverage_state: EvidenceState,
) -> PolicyCheck:
    record_key = _record_key(record, target)
    check_id = hashlib.sha256(
        "|".join(
            [
                capture_sha256,
                pack.profile.value,
                pack_digest,
                rule.id,
                check_outcome.value,
                target.value,
                record_key,
            ]
        ).encode("utf-8")
    ).hexdigest()
    return PolicyCheck(
        check_id=check_id,
        code=rule.id,
        category=_CHECK_CATEGORY[target.value],
        protocol=_protocol_from_context(context),
        affected_endpoint=_endpoint_from_context(context),
        record_type=EvidenceRecordType(target.value),
        record_key=record_key,
        outcome=check_outcome,
        evidence_state=coverage_state,
        title=rule.title,
    )


def _endpoint_from_context(context: Mapping[str, object]) -> str:
    flow = context.get("flow")
    if isinstance(flow, Mapping):
        resp = flow.get("resp")
        if isinstance(resp, Mapping) and resp.get("host") is not None:
            return f"{resp.get('host')}:{resp.get('port')}"
    return "unknown"


def _weakest_state(references: Sequence[EvidenceReference]) -> EvidenceState:
    if not references:
        return EvidenceState.INDETERMINATE
    return min(references, key=lambda item: _STATE_RANK[item.evidence_state]).evidence_state
