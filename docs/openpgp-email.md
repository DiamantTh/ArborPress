# OpenPGP email protection

ArborPress uses the existing durable mail outbox and SMTP profiles. OpenPGP is
applied to each one-recipient outbox delivery immediately before SMTP send;
there is no plugin mail bypass and no second queue. SMTP TLS protects the
transport connection, while PGP/MIME protects the message content.

## Keys and identity

The instance has a signing-only OpenPGP identity. `arborpress key generate
<name>` creates an Ed25519 signing key with a random passphrase; the private
key and passphrase are encrypted at rest using a domain-separated key derived
from `web.secret_key`. The generated instance key has no encryption subkey and
cannot decrypt recipient messages. Imported instance keys are rejected if they
contain a usable message-encryption key or subkey. `arborpress key import <file>
--passphrase-prompt` accepts a protected signing key, validates that it can
sign, and stores its protected material. `arborpress key rotate <name>` makes a
new key current while retaining the previous public key and key metadata.
`arborpress key status` displays fingerprints and status, never private
material. The admin mail page also supports generation, import, activation,
and signing/encryption policy changes; each sensitive mutation requires admin
RBAC, CSRF and a fresh WebAuthn step-up.

Users can paste or upload one public recipient key at `/auth/security`. Only
the public key is retained in `user_pgp_keys`, associated through `users.id`.
Private user keys and passphrases are neither requested nor stored. GnuPG
parsing requires one usable public key with an active encryption-capable key;
weak/unsupported key families, revoked/expired keys and private-key uploads
are rejected. The key User ID must contain the account's current email
address, and that address is checked again immediately before send. This is a
consistency rule, **not proof that the user controls that mailbox**. ArborPress
does not infer identity from a key display name or use an OpenPGP User ID to
change a message recipient. A queued registered recipient is pinned to its
local user ID; a changed email or disabled/deleted account fails closed.
Pre-Phase-15 outbox entries have no trustworthy historical account binding: if
their address currently belongs to a local account, delivery stops and the
original producer must create a newly bound message. ArborPress does not infer
that old mail belongs to whoever currently owns a reused address.

## Policy matrix

| Instance signing | Instance encryption required | User opted in | Recipient key | Result |
|---|---:|---:|---|---|
| off | no | no | absent or not selected | Plain message |
| on | no | no | absent or not selected | Signed PGP/MIME |
| off or on | no | yes | valid current key | Encrypted; also signed when instance signing is on |
| off or on | no | yes | missing, expired, revoked, mismatched or unusable | Delivery blocked; no plaintext downgrade |
| off or on | yes | either | valid current key | Encrypted; also signed when instance signing is on |
| off or on | yes | either | missing or unusable | Delivery blocked; no plaintext downgrade |
| off or on | yes | any external recipient | no local account key mapping | Delivery blocked |
| on | any | any | signing key missing/expired/unusable | Delivery blocked |

The default is signing off and mandatory encryption off. Users must opt in to
encryption, or an administrator can require it instance-wide. Turning on the
instance-wide requirement blocks external recipients and local accounts
without a current eligible public key. The admin UI states this effect. A key
that is stored but not opted into is not used for encryption unless the
instance requirement is enabled. The outbox snapshots the effective encryption
requirement when a message is queued, so an intervening opt-out or policy change
cannot downgrade that queued message to plaintext. Invalid keys never cause a
protected message to fall back to plaintext.

For encrypted messages ArborPress emits PGP/MIME `multipart/encrypted`. If
signing is enabled, the signed MIME body is encrypted first, so the signature
is verified after decryption. Signed-only messages use
`multipart/signed`. Text, HTML alternatives and bounded MIME attachments are
all included in the protected body. The outbox has one SMTP envelope recipient
per row; protected mail does not reveal other queued `To`/`Cc` recipients in
its headers. Subject, sender, recipient, routing and other transport headers
remain visible to mail infrastructure. Do not put confidential data in a
subject or custom header; OpenPGP does not hide classic email metadata.

## Runtime, failure and recovery

The runtime requires the system `gpg`/GnuPG executable and its agent. Ubuntu
and AlmaLinux ArborPress images install the corresponding runtime package.
Every operation uses a private temporary GnuPG home, fixed executable lookup,
argument arrays without a shell, bounded input and timeouts. Temporary agent
state is stopped and the private home removed. No keyserver or remote key
fetch is used. OpenPGP failures become bounded queue error codes; keys,
passphrases, message contents and tokens are not written to audit/log output.

The encrypted key rows are part of the ordinary database backup. Restoring
them also requires the exact `web.secret_key` value used to encrypt them. If
that secret is absent or changed, signing fails closed; restore the matching
secret from protected configuration backup or import/rotate a replacement
instance signing key. User public keys can be re-uploaded by their owners.
There is no instance decryption key or hidden recipient recovery key.

The CLI import command reads a local regular file (maximum 2 MiB), rejects
symlinks and never puts a passphrase in command arguments. Public user keys are
limited to 128 KiB. Mail attachments are limited to 20 files and 10 MiB total.
The outbox keeps message content until delivery/retention handling; this is
separate from OpenPGP key storage. SMTP acceptance is not proof of mailbox
delivery, and a crash after SMTP acceptance can still cause a retry duplicate.

## Checks

`tests/test_openpgp_mail.py` uses synthetic local GnuPG keys. It checks
PGP/MIME creation, decryption, signature validation, wrong-recipient failure,
SMTP capture, public-key/private-key separation, and policy fail-closed cases.
The tests do not contact a real provider or send public email. Interoperability
is limited to the key families supported by the installed GnuPG version and
the synthetic formats exercised by the test suite; ArborPress does not claim
coverage for every OpenPGP implementation or key format.
