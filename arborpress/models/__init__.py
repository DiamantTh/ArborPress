# arborpress/models/__init__.py
# Alle ORM-Modelle importieren, damit SQLAlchemy metadata vollständig ist
from arborpress.models.user import (  # noqa: F401
    AccountType,
    BackupCode,
    MFADevice,
    MFADeviceType,
    User,
    UserRole,
    WebAuthnCredential,
)
from arborpress.models.content import (  # noqa: F401
    Media,
    Page,
    PageType,
    Post,
    PostStatus,
    Tag,
)
from arborpress.models.mail import MailQueue, MailStatus  # noqa: F401
