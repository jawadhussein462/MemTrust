"""The rule catalogue: what each finding code means and how to fix it.

Every finding a scan reports carries a code such as `"secret_detected"`.
The code is the rule id, the same way Semgrep, Trivy, and Gitleaks key
their findings. This module describes each built-in rule once, so every
report format (HTML, Markdown, SARIF, JSON, terminal) shows the same title,
explanation, remediation steps, and references.

Severity and recommended action here mirror the `FindingSpec` on the check
that raises the code. A test keeps the two in sync.

Codes that are not in the catalogue (from a custom check, say) still render:
`rule_for` builds a generic rule from the code.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models.enums import Action, Severity
from .owasp import (
    ASI06_ID,
    ASI06_TITLE,
    ASI06_URL,
    LLM01_ID,
    LLM01_TITLE,
    LLM01_URL,
    LLM02_ID,
    LLM02_TITLE,
    LLM02_URL,
)

REPO_URL = "https://github.com/jawadhussein462/mimvo"
RULES_DOC_URL = f"{REPO_URL}#what-it-finds"

_CWE_URL = "https://cwe.mitre.org/data/definitions/{}.html"


@dataclass(frozen=True)
class Reference:
    """A link a reader can follow to learn more about a rule.

    Attributes:
        label: Short text for the link, such as `"CWE-312"`.
        url: Where the link goes.
    """

    label: str
    url: str


@dataclass(frozen=True)
class Rule:
    """One finding code, described for people who read reports.

    Attributes:
        id: The finding code, such as `"secret_detected"`. Stable.
        title: Short name shown as the finding's heading.
        category: Which check raises it: `"secrets"`, `"injection"`, or
            `"poisoning"`. `"custom"` for unknown codes.
        severity: Default severity for the code.
        action: Default recommended action for the code.
        summary: One sentence saying what was found.
        remediation: Ordered steps to fix it.
        owasp_id: OWASP item id, such as `"LLM02"`.
        owasp_title: OWASP item title.
        owasp_url: Link to the OWASP item.
        cwe: CWE ids that describe the weakness, such as `("CWE-312",)`.
    """

    id: str
    title: str
    category: str
    severity: Severity
    action: Action
    summary: str
    remediation: tuple[str, ...]
    owasp_id: str
    owasp_title: str
    owasp_url: str
    cwe: tuple[str, ...] = ()

    @property
    def owasp(self) -> str:
        """The OWASP reference as one string, such as `"LLM02: Sensitive ..."`."""
        return f"{self.owasp_id}: {self.owasp_title}"

    @property
    def help_uri(self) -> str:
        """Documentation for this rule."""
        return RULES_DOC_URL

    @property
    def references(self) -> tuple[Reference, ...]:
        """OWASP first, then each CWE, then the Mimvo rule docs."""
        refs = [Reference(self.owasp, self.owasp_url)]
        refs.extend(Reference(cwe, _CWE_URL.format(cwe.split("-", 1)[1])) for cwe in self.cwe)
        refs.append(Reference("Mimvo rules", self.help_uri))
        return tuple(refs)


_OWASP = {
    "secrets": (LLM02_ID, LLM02_TITLE, LLM02_URL),
    "injection": (LLM01_ID, LLM01_TITLE, LLM01_URL),
    "poisoning": (ASI06_ID, ASI06_TITLE, ASI06_URL),
}
_DEFAULT_CWE = {"injection": ("CWE-1427",), "poisoning": ("CWE-345",)}


def _rule(
    code: str,
    category: str,
    *,
    title: str,
    severity: Severity,
    action: Action,
    summary: str,
    remediation: tuple[str, ...],
    cwe: tuple[str, ...] | None = None,
) -> Rule:
    owasp_id, owasp_title, owasp_url = _OWASP[category]
    return Rule(
        id=code,
        title=title,
        category=category,
        severity=severity,
        action=action,
        summary=summary,
        remediation=remediation,
        owasp_id=owasp_id,
        owasp_title=owasp_title,
        owasp_url=owasp_url,
        cwe=_DEFAULT_CWE.get(category, ()) if cwe is None else cwe,
    )


_REVIEW_POISON = (
    "Read the record and confirm with its owner whether the statement is true.",
    "If it is not, quarantine or delete it so the agent stops retrieving it.",
    "Find the write path that stored it and add a write-time check there.",
)

_RULES: tuple[Rule, ...] = (
    _rule(
        "secret_detected",
        "secrets",
        title="Leaked secret",
        severity=Severity.CRITICAL,
        action=Action.DELETE,
        summary=(
            "The record contains a credential: an API key, token, password, private key, "
            "or connection string."
        ),
        remediation=(
            "Rotate or revoke the credential first. Deleting the record does not undo exposure.",
            "Delete the record from the store, and from any export or backup of it.",
            "Stop the write path from storing secrets, for example with a WriteGuard.",
        ),
        cwe=("CWE-312",),
    ),
    _rule(
        "pii_detected",
        "secrets",
        title="Personal data",
        severity=Severity.MEDIUM,
        action=Action.REVIEW,
        summary="The record contains personal data such as a name, email, or phone number.",
        remediation=(
            "Check whether the agent needs this data to do its job.",
            "Redact it, or apply your retention rule for personal data.",
            "Do not treat it as a credential to rotate.",
        ),
        cwe=("CWE-359",),
    ),
    _rule(
        "persistent_instruction",
        "injection",
        title="Hidden instruction",
        severity=Severity.HIGH,
        action=Action.REVIEW,
        summary=(
            "The record tries to override the agent's instructions, switch its persona, "
            "or hide something from the user. It will reach the prompt as trusted context."
        ),
        remediation=(
            "Read the record. Memory should hold facts and preferences, not orders to the agent.",
            "Delete it if it is an injection; it re-enters the prompt every time it is retrieved.",
            "Trace where it came from (a scraped page, a ticket, a tool result) and filter there.",
        ),
    ),
    _rule(
        "known_answer",
        "injection",
        title="Canary instruction dropped",
        severity=Severity.MEDIUM,
        action=Action.REVIEW,
        summary=(
            "Placed next to a canary instruction, the record made a language model ignore it."
        ),
        remediation=(
            "Review the record for embedded instructions.",
            "Delete or quarantine it if it hijacks the model.",
        ),
    ),
    _rule(
        "embedding_injection",
        "injection",
        title="Injection embedding",
        severity=Severity.MEDIUM,
        action=Action.REVIEW,
        summary="A classifier on the stored vector labels the record as prompt injection.",
        remediation=(
            "Review the record text for embedded instructions.",
            "Calibrate the classifier threshold on your own data if hits look benign.",
        ),
    ),
    _rule(
        "memory_poisoning",
        "poisoning",
        title="Poisoned fact",
        severity=Severity.HIGH,
        action=Action.QUARANTINE,
        summary=(
            "The record claims a security control is off: authentication, MFA, approval, "
            "or review. An agent that retrieves it may act on it."
        ),
        remediation=(
            "Quarantine the record so retrieval stops returning it.",
            "Confirm with the control's owner whether the claim is true.",
            "Delete it if false, and find the source that wrote it.",
        ),
    ),
    _rule(
        "destination_redirect",
        "poisoning",
        title="Destination redirect",
        severity=Severity.HIGH,
        action=Action.REVIEW,
        summary="The record routes payments or data to a new destination.",
        remediation=(
            "Confirm the change through a channel other than the agent's memory.",
            "Delete the record if nobody authorised the new destination.",
        ),
    ),
    _rule(
        "poisoning_cluster",
        "poisoning",
        title="Poisoning cluster",
        severity=Severity.LOW,
        action=Action.REVIEW,
        summary=(
            "The record is one of several near-identical records, the pattern of "
            "multi-document poisoning."
        ),
        remediation=(
            "Compare the records in the cluster; legitimate copies of a template also match.",
            "Remove the copies if they were planted to outvote the truth.",
        ),
    ),
    _rule(
        "hub_record",
        "poisoning",
        title="Retrieval hub",
        severity=Severity.LOW,
        action=Action.REVIEW,
        summary=(
            "The record is a nearest neighbour of unusually many others, so it is "
            "retrieved for many unrelated queries."
        ),
        remediation=(
            "Read the record; text written to match every query is a poisoning signal.",
            "Delete it if its content has no reason to be that central.",
        ),
    ),
    _rule(
        "adversarial_text",
        "poisoning",
        title="Adversarial text",
        severity=Severity.MEDIUM,
        action=Action.REVIEW,
        summary="Part of the record reads as machine-optimised rather than natural text.",
        remediation=(
            "Look for gibberish suffixes or token soup in the record.",
            "Delete it if the span was optimised to steer retrieval or generation.",
        ),
        cwe=("CWE-1039",),
    ),
    _rule(
        "embedding_mismatch",
        "poisoning",
        title="Tampered vector",
        severity=Severity.MEDIUM,
        action=Action.QUARANTINE,
        summary="The stored vector does not match a fresh embedding of the record text.",
        remediation=(
            "Quarantine the record; its vector may have been written directly.",
            "Re-embed it with the store's model, or delete it.",
            "Check who has write access to the vector column.",
        ),
    ),
    _rule(
        "temporal_contradiction",
        "poisoning",
        title="Contradicts older memory",
        severity=Severity.MEDIUM,
        action=Action.REVIEW,
        summary="A newer record contradicts the older records around it.",
        remediation=_REVIEW_POISON,
    ),
    _rule(
        "retrieval_flip",
        "poisoning",
        title="Answer flip",
        severity=Severity.MEDIUM,
        action=Action.REVIEW,
        summary="Removing the record changes the answers to questions about its topic.",
        remediation=_REVIEW_POISON,
    ),
)

RULES: dict[str, Rule] = {rule.id: rule for rule in _RULES}


def rule_for(code: str) -> Rule:
    """Look up the rule for a finding code.

    Args:
        code: A finding code such as `"secret_detected"`.

    Returns:
        The catalogue entry, or a generic rule for codes from custom
        checks: the code as the title, medium severity, review, ASI06.
    """
    rule = RULES.get(code)
    if rule is not None:
        return rule
    return Rule(
        id=code,
        title=code.replace("_", " ").replace("-", " ").capitalize(),
        category="custom",
        severity=Severity.MEDIUM,
        action=Action.REVIEW,
        summary="Raised by a custom check.",
        remediation=("Review the record against the custom check's documentation.",),
        owasp_id=ASI06_ID,
        owasp_title=ASI06_TITLE,
        owasp_url=ASI06_URL,
    )


__all__ = ["REPO_URL", "RULES", "RULES_DOC_URL", "Reference", "Rule", "rule_for"]
