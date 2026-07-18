"""Camada de acesso ao banco de dados (SQLite).

Todas as consultas usam parâmetros (?) — nunca interpolação de string —
para eliminar risco de SQL Injection.
"""
import sqlite3
from pathlib import Path

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS usuarios (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario         TEXT NOT NULL,
    email           TEXT NOT NULL UNIQUE COLLATE NOCASE,
    uf              TEXT NOT NULL,
    senha_hash      TEXT NOT NULL,
    profile_image   TEXT NOT NULL DEFAULT '',
    descricao       TEXT NOT NULL DEFAULT '',
    data_nascimento TEXT NOT NULL DEFAULT '',
    genero          TEXT NOT NULL DEFAULT '',
    biografia       TEXT NOT NULL DEFAULT '',
    is_admin        INTEGER NOT NULL DEFAULT 0,
    falhas_login    INTEGER NOT NULL DEFAULT 0,
    bloqueado_ate   TEXT,
    criado_em       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS auditoria (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER,
    email      TEXT,
    acao       TEXT NOT NULL,
    ip         TEXT,
    criado_em  TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(current_app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db


def close_db(_exc=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_app(app):
    Path(app.config['DATABASE']).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(app.config['DATABASE']) as conn:
        conn.executescript(SCHEMA)
    app.teardown_appcontext(close_db)


def registrar_auditoria(acao, usuario_id=None, email=None, ip=None):
    """Grava uma trilha de auditoria para ações críticas (login, cadastro, etc.)."""
    db = get_db()
    db.execute(
        'INSERT INTO auditoria (usuario_id, email, acao, ip) VALUES (?, ?, ?, ?)',
        (usuario_id, email, acao, ip),
    )
    db.commit()
