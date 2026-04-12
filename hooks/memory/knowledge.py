"""Cross-session knowledge index.

Project-level SQLite DB that indexes session summaries and key entities
across all sessions. Enables "who solved this before?" and cross-session
context injection on resume.
"""
import hashlib
import json
import os
import re
import sqlite3
from typing import List, Optional

from . import db as archive_db

VAULT_DIR = archive_db.VAULT_DIR

KNOWLEDGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS session_summaries (
    session_id    TEXT PRIMARY KEY,
    project_dir   TEXT,
    goal          TEXT,
    plan          TEXT,
    done          TEXT,
    blocked       TEXT,
    decisions     TEXT,
    key_files     TEXT,            -- JSON array of touched files
    turn_count    INTEGER DEFAULT 0,
    first_seen    TEXT,
    last_updated  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS entities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    entity_type TEXT NOT NULL,     -- 'file', 'function', 'decision', 'migration', 'error'
    name        TEXT NOT NULL,
    context     TEXT,             -- one-line context
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE VIRTUAL TABLE IF NOT EXISTS entities_fts USING fts5(
    name, context, entity_type,
    content='entities', content_rowid='id',
    tokenize='porter unicode61'
);

CREATE TRIGGER IF NOT EXISTS entities_ai AFTER INSERT ON entities BEGIN
    INSERT INTO entities_fts(rowid, name, context, entity_type)
    VALUES (new.id, new.name, new.context, new.entity_type);
END;

CREATE TRIGGER IF NOT EXISTS entities_ad AFTER DELETE ON entities BEGIN
    INSERT INTO entities_fts(entities_fts, rowid, name, context, entity_type)
    VALUES ('delete', old.id, old.name, old.context, old.entity_type);
END;

CREATE INDEX IF NOT EXISTS idx_entities_session ON entities(session_id);
CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type, name);
CREATE INDEX IF NOT EXISTS idx_summaries_project ON session_summaries(project_dir);
"""


def _project_hash(cwd: str) -> str:
    """Deterministic hash for project directory."""
    return hashlib.sha256(cwd.encode()).hexdigest()[:12]


def get_knowledge_db(cwd: str) -> sqlite3.Connection:
    """Get or create project-level knowledge.db."""
    projects_dir = os.path.join(VAULT_DIR, "projects")
    os.makedirs(projects_dir, mode=0o700, exist_ok=True)
    db_path = os.path.join(projects_dir, f"{_project_hash(cwd)}.db")
    db = sqlite3.connect(db_path)
    db.executescript(KNOWLEDGE_SCHEMA)
    return db


def update_session_knowledge(session_id: str, cwd: str):
    """
    Update knowledge.db with current session's state.
    Called during PreCompact after session_state.md is generated.
    """
    if not session_id or not cwd:
        return

    # Read session_state.md
    state_path = os.path.join(VAULT_DIR, f"{session_id}_state.md")
    if not os.path.isfile(state_path):
        return

    sections = _parse_state_file(state_path)

    # Get file list from session archive
    key_files = []
    try:
        session_db = archive_db.get_db(session_id)
        rows = session_db.execute("""
            SELECT DISTINCT files_touched FROM turns
            WHERE session_id = ? AND files_touched IS NOT NULL
            ORDER BY line_number DESC LIMIT 50
        """, (session_id,)).fetchall()
        for (ft,) in rows:
            try:
                files = json.loads(ft)
                key_files.extend(files)
            except (json.JSONDecodeError, TypeError):
                pass
        # Deduplicate, keep top 20
        seen = set()
        unique_files = []
        for f in key_files:
            if f not in seen:
                seen.add(f)
                unique_files.append(f)
        key_files = unique_files[:20]

        turn_count = session_db.execute(
            "SELECT COUNT(*) FROM turns WHERE session_id = ?", (session_id,)
        ).fetchone()[0]
        first_seen = session_db.execute(
            "SELECT MIN(created_at) FROM turns WHERE session_id = ?", (session_id,)
        ).fetchone()[0]
        session_db.close()
    except Exception:
        turn_count = 0
        first_seen = None

    # Upsert into knowledge.db
    kdb = get_knowledge_db(cwd)

    kdb.execute("""
        INSERT INTO session_summaries
        (session_id, project_dir, goal, plan, done, blocked, decisions,
         key_files, turn_count, first_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(session_id) DO UPDATE SET
            goal = excluded.goal,
            plan = excluded.plan,
            done = excluded.done,
            blocked = excluded.blocked,
            decisions = excluded.decisions,
            key_files = excluded.key_files,
            turn_count = excluded.turn_count,
            last_updated = datetime('now')
    """, (
        session_id, cwd,
        sections.get("goal", ""),
        "\n".join(sections.get("plan", [])),
        "\n".join(sections.get("done", [])),
        "\n".join(sections.get("blocked", [])),
        "\n".join(sections.get("decisions", [])),
        json.dumps(key_files),
        turn_count,
        first_seen,
    ))

    # Extract and index entities
    _index_entities(kdb, session_id, sections, key_files)

    kdb.commit()
    kdb.close()


def search_knowledge(cwd: str, query: str, current_session_id: str = "",
                     limit: int = 5) -> str:
    """
    Search knowledge.db for relevant prior sessions.
    Searches both session_summaries (goal/done/decisions) and entities FTS.
    Returns formatted context string for additionalContext injection.
    """
    if not cwd:
        return ""

    projects_dir = os.path.join(VAULT_DIR, "projects")
    db_path = os.path.join(projects_dir, f"{_project_hash(cwd)}.db")
    if not os.path.isfile(db_path):
        return ""

    kdb = get_knowledge_db(cwd)
    safe_query = _sanitize_fts5(query)
    results = []

    try:
        # 1. Search session summaries (goal, done, decisions text)
        # Split query into words and match ANY word (OR)
        import re as _re
        words = _re.findall(r'[\w]+', query, _re.UNICODE)
        if words:
            like_clauses = []
            params = [current_session_id]
            for w in words[:5]:  # limit to 5 words to avoid huge queries
                like_clauses.append(
                    "(goal LIKE '%' || ? || '%' OR done LIKE '%' || ? || '%' OR decisions LIKE '%' || ? || '%')"
                )
                params.extend([w, w, w])
            params.append(limit)
            where = " OR ".join(like_clauses)
            summary_hits = kdb.execute(f"""
                SELECT session_id, goal, done, decisions, last_updated
                FROM session_summaries
                WHERE session_id != ? AND ({where})
                ORDER BY last_updated DESC LIMIT ?
            """, params).fetchall()
        else:
            summary_hits = []

        for sid, goal, done, decisions, updated in summary_hits:
            results.append({
                "session_id": sid[:8],
                "type": "session",
                "name": goal or "unknown goal",
                "context": (done or "")[:200],
                "goal": goal or "",
                "updated": updated or "",
            })

        # 2. Search entities via FTS5 (more precise, handles stemming)
        entity_hits = kdb.execute("""
            SELECT e.session_id, e.entity_type, e.name, e.context,
                   s.goal, s.last_updated
            FROM entities_fts f
            JOIN entities e ON e.id = f.rowid
            LEFT JOIN session_summaries s ON s.session_id = e.session_id
            WHERE entities_fts MATCH ? AND e.session_id != ?
            ORDER BY rank LIMIT ?
        """, (safe_query, current_session_id, limit)).fetchall()

        for sid, etype, name, ctx, goal, updated in entity_hits:
            results.append({
                "session_id": sid[:8],
                "type": etype,
                "name": name,
                "context": ctx or "",
                "goal": goal or "",
                "updated": updated or "",
            })
    except Exception:
        pass

    kdb.close()

    if not results:
        return ""

    # Deduplicate by session_id
    lines = ["## Prior Session Knowledge"]
    seen_sessions = set()
    for r in results:
        sid = r["session_id"]
        if sid not in seen_sessions:
            seen_sessions.add(sid)
            if r["goal"]:
                lines.append(f"\n**Session {sid}** ({r['updated'][:10]}): {r['goal']}")
        if r["type"] != "session":
            lines.append(f"  - [{r['type']}] {r['name']}: {r['context']}")

    return "\n".join(lines)


def _index_entities(kdb: sqlite3.Connection, session_id: str,
                    sections: dict, key_files: list):
    """Extract and index entities from session state."""
    # Clear old entities for this session (re-index)
    kdb.execute("DELETE FROM entities WHERE session_id = ?", (session_id,))

    entities = []

    # Files
    for f in key_files:
        entities.append(("file", f, f"touched in session"))

    # Decisions
    for d in sections.get("decisions", []):
        d = d.lstrip("- ")
        entities.append(("decision", d[:100], d))

    # Done items (completed work)
    for d in sections.get("done", []):
        d = d.lstrip("- ")
        entities.append(("completed", d[:100], d))

        # Extract migration numbers
        for m in re.findall(r"migration[_ ]?(\d+)", d, re.I):
            entities.append(("migration", f"migration_{m}", d))

    # Blocked items
    for b in sections.get("blocked", []):
        b = b.lstrip("- ")
        entities.append(("blocker", b[:100], b))

    for etype, name, ctx in entities:
        kdb.execute("""
            INSERT INTO entities (session_id, entity_type, name, context)
            VALUES (?, ?, ?, ?)
        """, (session_id, etype, name, ctx))


def _parse_state_file(state_path: str) -> dict:
    """Parse session_state.md into sections dict."""
    sections = {"goal": "", "plan": [], "done": [], "blocked": [], "decisions": []}
    try:
        with open(state_path) as f:
            content = f.read()
    except OSError:
        return sections

    current = None
    for line in content.splitlines():
        s = line.strip()
        if s.startswith("## Goal"):
            current = "goal"
        elif s.startswith("## Plan"):
            current = "plan"
        elif s.startswith("## Done"):
            current = "done"
        elif s.startswith("## Blocked"):
            current = "blocked"
        elif s.startswith("## Key Decision"):
            current = "decisions"
        elif s.startswith("## ") or s.startswith("# "):
            current = None
        elif current and s:
            if current == "goal":
                sections["goal"] = s
            else:
                sections[current].append(s)
    return sections


def _sanitize_fts5(raw: str) -> str:
    tokens = re.findall(r"[\w]+", raw, re.UNICODE)
    if not tokens:
        return '""'
    return " ".join(f'"{t}"' for t in tokens)
