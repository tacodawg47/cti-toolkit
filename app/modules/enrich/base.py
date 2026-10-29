"""
Small shared helpers for vendor clients.

Every client builds a VendorResult the same way, so this keeps that one line
in one place instead of repeating it in each module.
"""

from ...core.models import VendorResult


def vendor_result(vendor: str, itype: str, value: str, **kw) -> VendorResult:
    """Build a VendorResult with the common fields filled in."""
    return VendorResult(source=vendor, indicator=value, indicator_type=itype, **kw)
