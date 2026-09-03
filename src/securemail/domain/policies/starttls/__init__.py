"""STARTTLS/STLS policy functions."""

from securemail.domain.policies.starttls.imap_upgrade import imap_upgrade
from securemail.domain.policies.starttls.implicit_tls import correlate_implicit_tls
from securemail.domain.policies.starttls.pop3_upgrade import pop3_upgrade
from securemail.domain.policies.starttls.smtp_upgrade import smtp_upgrade

__all__ = [
    "correlate_implicit_tls",
    "imap_upgrade",
    "pop3_upgrade",
    "smtp_upgrade",
]
