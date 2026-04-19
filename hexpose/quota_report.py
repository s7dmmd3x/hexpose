"""Human-readable report for quota results."""
from __future__ import annotations
from hexpose.match_quota import QuotaResult


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def format_quota_result(qr: QuotaResult) -> str:
    lines = []
    status = _c("CAPPED", "33") if qr.capped else _c("OK", "32")
    lines.append(f"Quota status : {status}")
    lines.append(f"Matches kept : {_c(str(len(qr.matches)), '36')}")
    if qr.dropped:
        lines.append(f"Dropped      : {_c(str(qr.dropped), '31')}")
    return "\n".join(lines)


def quota_summary(qr: QuotaResult) -> str:
    if not qr.dropped:
        return "All matches within quota."
    return (
        f"{qr.dropped} match(es) dropped by quota; "
        f"{len(qr.matches)} kept{' (total cap reached)' if qr.capped else ''}."
    )
