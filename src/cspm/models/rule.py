"""Validated security rule metadata model."""

from pydantic import BaseModel, field_validator, model_validator

from cspm.models.enums import Severity


class Rule(BaseModel):
    """Metadata describing a security rule and its remediation guidance."""

    rule_id: str
    title: str
    resource_type: str
    severity: Severity
    cis_control: str | None = None
    cis_version: str | None = None
    remediation_text: str

    @field_validator("rule_id", "title", "resource_type", "remediation_text")
    @classmethod
    def required_text_must_not_be_blank(cls, value: str) -> str:
        """Reject required text that is empty or contains only whitespace."""
        if not value.strip():
            raise ValueError("must not be empty or whitespace-only")
        return value

    @field_validator("cis_control", "cis_version")
    @classmethod
    def optional_text_must_not_be_blank(cls, value: str | None) -> str | None:
        """Allow absent CIS mapping text, but reject blank supplied values."""
        if value is not None and not value.strip():
            raise ValueError("must not be empty or whitespace-only")
        return value

    @model_validator(mode="after")
    def cis_mapping_must_be_complete(self) -> "Rule":
        """Require the CIS control and version to be both present or absent."""
        if (self.cis_control is None) != (self.cis_version is None):
            raise ValueError("cis_control and cis_version must be provided together")
        return self
