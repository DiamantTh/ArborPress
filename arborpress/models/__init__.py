# arborpress/models/__init__.py
# Alle ORM-Modelle importieren, damit SQLAlchemy metadata vollständig ist
from arborpress.models.user import (  # noqa: F401
    AccountType,
    BackupCode,
    MFADevice,
    MFADeviceType,
    User,
    UserPGPKey,
    UserRole,
    WebAuthnCredential,
)
from arborpress.models.content import (  # noqa: F401
    Category,
    Comment,
    CommentStatus,
    Media,
    Page,
    PageType,
    Post,
    PostAccessToken,
    PostRevision,
    PostStatus,
    PostVisibility,
    Tag,
)
from arborpress.models.mail import MailQueue, MailStatus  # noqa: F401
