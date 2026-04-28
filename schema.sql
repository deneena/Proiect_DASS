DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tickets;
DROP TABLE IF EXISTS audit_logs;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email STRING UNIQUE NOT NULL,
    password_hash STRING NOT NULL,
    role STRING NOT NULL default 'ANALYST',
    created_at TIMESTAMP NOT NULL default current_timestamp,
    locked BOOLEAN NOT NULL default false,
    CONSTRAINT chk_UserRole CHECK (upper(role) = 'ANALYST' or upper(role) = 'MANAGER')
);

CREATE TABLE tickets(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title STRING NOT NULL,
    description TEXT NOT NULL,
    severity STRING NOT NULL,
    status STRING NOT NULL,
    owner_id INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL default current_timestamp,
    updated_at TIMESTAMP NOT NULL default current_timestamp,
    FOREIGN KEY(owner_id) REFERENCES users(id),
    CONSTRAINT chk_TicketSeverity CHECK (upper(severity) = 'LOW' or upper(severity) = 'MED' or upper(severity) = 'HIGH'),
    CONSTRAINT chk_TicketStatus CHECK (upper(status) = 'OPEN' or upper(status) = 'IN_PROGRESS' or upper(status) = 'RESOLVED')
);

CREATE TABLE audit_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action STRING NOT NULL,
    resource STRING NOT NULL,
    resource_id STRING NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    ip_address STRING NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN reset_token STRING;
ALTER TABLE users ADD COLUMN reset_token_expiry TIMESTAMP;