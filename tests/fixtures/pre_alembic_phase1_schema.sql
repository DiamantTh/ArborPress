-- Frozen SQLite DDL from the Phase 1 pre-Alembic create_all_tables schema.
-- Source commit: 41d8dc9fc7f0d18781cd45acdf4ae86262e9d4c8
PRAGMA foreign_keys=ON;
CREATE TABLE actor_keypairs (
	id VARCHAR(36) NOT NULL,
	user_id VARCHAR(36) NOT NULL,
	key_id_url VARCHAR(512) NOT NULL,
	public_key_pem TEXT NOT NULL,
	private_key_enc BLOB NOT NULL,
	algorithm VARCHAR(32) NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	rotated_at DATETIME,
	PRIMARY KEY (id),
	UNIQUE (user_id),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
)
;
CREATE TABLE ap_followers (
	id VARCHAR(36) NOT NULL,
	local_user_id VARCHAR(36) NOT NULL,
	remote_actor_uri VARCHAR(2048) NOT NULL,
	remote_display_name VARCHAR(256),
	remote_inbox_uri VARCHAR(2048),
	direction VARCHAR(8) NOT NULL,
	state VARCHAR(8) NOT NULL,
	activity_id VARCHAR(512),
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_follower_local_remote_dir UNIQUE (local_user_id, remote_actor_uri, direction),
	FOREIGN KEY(local_user_id) REFERENCES users (id) ON DELETE CASCADE
)
;
CREATE TABLE audit_events (
	id INTEGER NOT NULL,
	event_type VARCHAR(64) NOT NULL,
	actor_id VARCHAR(36),
	actor_name VARCHAR(32),
	target_id VARCHAR(36),
	ip VARCHAR(45),
	user_agent VARCHAR(512),
	outcome VARCHAR(16) NOT NULL,
	detail TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	PRIMARY KEY (id)
)
;
CREATE TABLE auth_pending (
	id VARCHAR(36) NOT NULL,
	user_id VARCHAR(36),
	purpose VARCHAR(48) NOT NULL,
	challenge BLOB,
	label VARCHAR(128),
	username VARCHAR(32),
	display_name VARCHAR(128),
	email VARCHAR(254),
	context TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	expires_at DATETIME NOT NULL,
	consumed_at DATETIME,
	PRIMARY KEY (id),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
)
;
CREATE TABLE auth_stepup_grants (
	id VARCHAR(36) NOT NULL,
	user_id VARCHAR(36) NOT NULL,
	session_id VARCHAR(36) NOT NULL,
	action VARCHAR(48) NOT NULL,
	target VARCHAR(512) NOT NULL,
	auth_method VARCHAR(32) DEFAULT 'unknown' NOT NULL,
	assurance_level VARCHAR(32) DEFAULT 'unknown' NOT NULL,
	confirming_credential_id VARCHAR(36),
	confirming_mfa_device_id VARCHAR(36),
	created_at DATETIME NOT NULL,
	expires_at DATETIME NOT NULL,
	consumed_at DATETIME,
	PRIMARY KEY (id),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
)
;
CREATE TABLE backup_codes (
	id VARCHAR(36) NOT NULL,
	user_id VARCHAR(36) NOT NULL,
	code_hash VARCHAR(128) NOT NULL,
	used BOOLEAN NOT NULL,
	used_at DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
)
;
CREATE TABLE categories (
	id INTEGER NOT NULL,
	slug VARCHAR(128) NOT NULL,
	label VARCHAR(128) NOT NULL,
	description TEXT,
	parent_id INTEGER,
	sort_order INTEGER NOT NULL,
	lang VARCHAR(8),
	PRIMARY KEY (id),
	UNIQUE (slug),
	FOREIGN KEY(parent_id) REFERENCES categories (id) ON DELETE SET NULL
)
;
CREATE TABLE comments (
	id VARCHAR(36) NOT NULL,
	post_id VARCHAR(36) NOT NULL,
	author_name VARCHAR(128) NOT NULL,
	author_email VARCHAR(256) NOT NULL,
	author_url VARCHAR(512),
	body TEXT NOT NULL,
	status VARCHAR(9) NOT NULL,
	confirmation_token VARCHAR(64) NOT NULL,
	confirmed_at DATETIME,
	approved_at DATETIME,
	quote_of_id VARCHAR(36),
	mod_note TEXT,
	ip_address VARCHAR(64),
	user_agent VARCHAR(512),
	country_code VARCHAR(2),
	rdap_json TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(post_id) REFERENCES posts (id) ON DELETE CASCADE,
	FOREIGN KEY(quote_of_id) REFERENCES comments (id) ON DELETE SET NULL
)
;
CREATE TABLE instance_keypair (
	id INTEGER NOT NULL,
	key_id_url VARCHAR(512) NOT NULL,
	public_key_pem TEXT NOT NULL,
	private_key_enc BLOB NOT NULL,
	algorithm VARCHAR(32) NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	rotated_at DATETIME,
	PRIMARY KEY (id)
)
;
CREATE TABLE mail_queue (
	id VARCHAR(36) NOT NULL,
	idempotency_key VARCHAR(128) NOT NULL,
	recipient VARCHAR(254) NOT NULL,
	subject VARCHAR(512) NOT NULL,
	body_text TEXT NOT NULL,
	body_html TEXT,
	pgp_encrypted BOOLEAN NOT NULL,
	status VARCHAR(9) NOT NULL,
	attempts INTEGER NOT NULL,
	next_attempt_at DATETIME,
	last_error VARCHAR(512),
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	sent_at DATETIME,
	PRIMARY KEY (id),
	UNIQUE (idempotency_key)
)
;
CREATE TABLE media (
	id VARCHAR(36) NOT NULL,
	uploader_id VARCHAR(36),
	filename VARCHAR(256) NOT NULL,
	mime_type VARCHAR(128) NOT NULL,
	size_bytes INTEGER NOT NULL,
	storage_path VARCHAR(512) NOT NULL,
	alt_text VARCHAR(512),
	width INTEGER,
	height INTEGER,
	original_url VARCHAR(1024),
	uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(uploader_id) REFERENCES users (id) ON DELETE SET NULL
)
;
CREATE TABLE mfa_devices (
	id VARCHAR(36) NOT NULL,
	user_id VARCHAR(36) NOT NULL,
	device_type VARCHAR(6) NOT NULL,
	label VARCHAR(128) NOT NULL,
	secret_enc BLOB NOT NULL,
	is_active BOOLEAN NOT NULL,
	verification_status VARCHAR(32) DEFAULT 'unknown' NOT NULL,
	plugin_id VARCHAR(64),
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	last_used_at DATETIME,
	PRIMARY KEY (id),
	CONSTRAINT uq_user_mfa_label UNIQUE (user_id, label),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
)
;
CREATE TABLE oembed_cache (
	id VARCHAR(36) NOT NULL,
	url VARCHAR(1024) NOT NULL,
	provider_name VARCHAR(128),
	html TEXT NOT NULL,
	fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	expires_at DATETIME NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (url)
)
;
CREATE TABLE pages (
	id VARCHAR(36) NOT NULL,
	slug VARCHAR(256) NOT NULL,
	slug_old VARCHAR(256),
	title VARCHAR(512) NOT NULL,
	body_md TEXT NOT NULL,
	body_html TEXT NOT NULL,
	page_type VARCHAR(9) NOT NULL,
	lang VARCHAR(8),
	is_published BOOLEAN NOT NULL,
	visibility VARCHAR(7) NOT NULL,
	noindex BOOLEAN NOT NULL,
	show_in_footer BOOLEAN NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	PRIMARY KEY (id)
)
;
CREATE TABLE post_access_tokens (
	id VARCHAR(36) NOT NULL,
	post_id VARCHAR(36) NOT NULL,
	label VARCHAR(128) NOT NULL,
	token_hash VARCHAR(256) NOT NULL,
	max_uses INTEGER,
	use_count INTEGER NOT NULL,
	expires_at DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(post_id) REFERENCES posts (id) ON DELETE CASCADE
)
;
CREATE TABLE post_categories (
	post_id VARCHAR(36) NOT NULL,
	category_id INTEGER NOT NULL,
	PRIMARY KEY (post_id, category_id),
	FOREIGN KEY(post_id) REFERENCES posts (id) ON DELETE CASCADE,
	FOREIGN KEY(category_id) REFERENCES categories (id) ON DELETE CASCADE
)
;
CREATE TABLE post_revisions (
	id VARCHAR(36) NOT NULL,
	post_id VARCHAR(36) NOT NULL,
	rev_number INTEGER NOT NULL,
	title VARCHAR(512) NOT NULL,
	body_md TEXT NOT NULL,
	diff_to_prev TEXT,
	changed_by_id VARCHAR(36),
	change_summary VARCHAR(256),
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(post_id) REFERENCES posts (id) ON DELETE CASCADE,
	FOREIGN KEY(changed_by_id) REFERENCES users (id) ON DELETE SET NULL
)
;
CREATE TABLE post_tags (
	post_id VARCHAR(36) NOT NULL,
	tag_id INTEGER NOT NULL,
	PRIMARY KEY (post_id, tag_id),
	FOREIGN KEY(post_id) REFERENCES posts (id) ON DELETE CASCADE,
	FOREIGN KEY(tag_id) REFERENCES tags (id) ON DELETE CASCADE
)
;
CREATE TABLE posts (
	id VARCHAR(36) NOT NULL,
	short_id VARCHAR(12) NOT NULL,
	author_id VARCHAR(36),
	slug VARCHAR(256) NOT NULL,
	slug_old VARCHAR(256),
	title VARCHAR(512) NOT NULL,
	body_md TEXT NOT NULL,
	body_html TEXT NOT NULL,
	body_json JSON,
	excerpt TEXT,
	status VARCHAR(9) NOT NULL,
	visibility VARCHAR(7) NOT NULL,
	lang VARCHAR(8),
	ap_object_id VARCHAR(512),
	captcha_type VARCHAR(32),
	is_pinned BOOLEAN NOT NULL,
	is_featured BOOLEAN NOT NULL,
	noindex BOOLEAN NOT NULL,
	reading_time_min INTEGER NOT NULL,
	published_at DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (short_id),
	FOREIGN KEY(author_id) REFERENCES users (id) ON DELETE SET NULL
)
;
CREATE TABLE site_settings (
	"key" VARCHAR(64) NOT NULL,
	value TEXT NOT NULL,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	updated_by VARCHAR(64),
	PRIMARY KEY ("key")
)
;
CREATE TABLE tags (
	id INTEGER NOT NULL,
	slug VARCHAR(128) NOT NULL,
	label VARCHAR(128) NOT NULL,
	lang VARCHAR(8),
	PRIMARY KEY (id),
	UNIQUE (slug)
)
;
CREATE TABLE user_pgp_keys (
	id VARCHAR(36) NOT NULL,
	user_id VARCHAR(36) NOT NULL,
	label VARCHAR(128) NOT NULL,
	public_key_armored TEXT NOT NULL,
	fingerprint VARCHAR(64) NOT NULL,
	use_for_signing BOOLEAN NOT NULL,
	use_for_encryption BOOLEAN NOT NULL,
	is_primary_signing BOOLEAN NOT NULL,
	expires_at DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	last_used_at DATETIME,
	PRIMARY KEY (id),
	CONSTRAINT uq_user_pgp_fingerprint UNIQUE (user_id, fingerprint),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
)
;
CREATE TABLE user_sessions (
	id VARCHAR(36) NOT NULL,
	user_id VARCHAR(36) NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	expires_at DATETIME NOT NULL,
	last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	client_ip VARCHAR(45),
	user_agent VARCHAR(512),
	is_tls BOOLEAN NOT NULL,
	is_cli BOOLEAN NOT NULL,
	is_valid BOOLEAN NOT NULL,
	auth_method VARCHAR(64) DEFAULT 'unknown' NOT NULL,
	assurance_level VARCHAR(32) DEFAULT 'unknown' NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
)
;
CREATE TABLE users (
	id VARCHAR(36) NOT NULL,
	username VARCHAR(32) NOT NULL,
	display_name VARCHAR(128) NOT NULL,
	email VARCHAR(254),
	account_type VARCHAR(11) NOT NULL,
	role VARCHAR(9) NOT NULL,
	is_active BOOLEAN NOT NULL,
	legacy_password_hash TEXT,
	legacy_password_enabled BOOLEAN NOT NULL,
	require_uv BOOLEAN NOT NULL,
	require_stepup BOOLEAN NOT NULL,
	sso_disabled BOOLEAN NOT NULL,
	federation_opt_out BOOLEAN NOT NULL,
	failed_login_count INTEGER DEFAULT '0' NOT NULL,
	locked_until DATETIME,
	bio TEXT,
	website VARCHAR(512),
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (username),
	UNIQUE (email)
)
;
CREATE TABLE webauthn_credentials (
	id VARCHAR(36) NOT NULL,
	user_id VARCHAR(36) NOT NULL,
	label VARCHAR(128) NOT NULL,
	credential_id BLOB NOT NULL,
	public_key BLOB NOT NULL,
	sign_count INTEGER NOT NULL,
	transport VARCHAR(32),
	is_platform BOOLEAN,
	uv_capable BOOLEAN NOT NULL,
	aaguid VARCHAR(64),
	transports TEXT,
	authenticator_attachment VARCHAR(32),
	backup_eligible BOOLEAN,
	backup_state BOOLEAN,
	verification_status VARCHAR(32) DEFAULT 'unknown' NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	last_used_at DATETIME,
	PRIMARY KEY (id),
	CONSTRAINT uq_user_credential_label UNIQUE (user_id, label),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE,
	UNIQUE (credential_id)
)
;
CREATE INDEX ix_audit_events_actor_id ON audit_events (actor_id)
;
CREATE INDEX ix_audit_events_created_at ON audit_events (created_at)
;
CREATE INDEX ix_audit_events_event_type ON audit_events (event_type)
;
CREATE INDEX ix_audit_events_target_id ON audit_events (target_id)
;
CREATE INDEX ix_auth_pending_consumed_at ON auth_pending (consumed_at)
;
CREATE INDEX ix_auth_pending_expires_at ON auth_pending (expires_at)
;
CREATE INDEX ix_auth_pending_purpose ON auth_pending (purpose)
;
CREATE INDEX ix_auth_pending_user_id ON auth_pending (user_id)
;
CREATE INDEX ix_auth_stepup_grants_action ON auth_stepup_grants (action)
;
CREATE INDEX ix_auth_stepup_grants_expires_at ON auth_stepup_grants (expires_at)
;
CREATE INDEX ix_auth_stepup_grants_session_id ON auth_stepup_grants (session_id)
;
CREATE INDEX ix_auth_stepup_grants_user_id ON auth_stepup_grants (user_id)
;
CREATE INDEX ix_media_original_url ON media (original_url);
