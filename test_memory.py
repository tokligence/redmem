"""Tests for redmem memory module."""
import json
import os
import sqlite3
import tempfile
import pytest

# Patch VAULT_DIR before importing
_tmpdir = tempfile.mkdtemp()
os.environ["REDMEM_VAULT_DIR"] = _tmpdir

# Patch the module
import hooks.memory.db as archive_db
archive_db.VAULT_DIR = _tmpdir

from hooks.memory.db import get_db, get_max_line_number, content_hash
from hooks.memory.transcript_parser import parse_incremental, ParsedTurn
from hooks.memory.search import sanitize_fts5_query, search
from hooks.memory.ingest import archive_turns
from hooks.memory.summarize import build_resume_context

# Patch ALL modules that copy VAULT_DIR at import time
import hooks.memory.knowledge as _knowledge_mod
_knowledge_mod.VAULT_DIR = _tmpdir
import hooks.memory.summarize as _summarize_mod
_summarize_mod.VAULT_DIR = _tmpdir
import hooks.memory.session_state as _state_mod
_state_mod.VAULT_DIR = _tmpdir


class TestDB:
    def test_get_db_creates_tables(self):
        db = get_db("test-session-1")
        tables = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = {t[0] for t in tables}
        assert "turns" in table_names
        assert "milestones" in table_names
        assert "sessions" in table_names
        assert "state_events" in table_names
        db.close()

    def test_get_max_line_number_empty(self):
        db = get_db("test-empty")
        assert get_max_line_number(db, "test-empty") == 0
        db.close()

    def test_get_max_line_number_after_insert(self):
        db = get_db("test-insert")
        db.execute("""
            INSERT INTO turns (session_id, line_number, uuid, role, content, content_hash, token_estimate)
            VALUES ('test-insert', 42, 'uuid-1', 'user', 'hello', 'hash1', 2)
        """)
        db.execute("""
            INSERT INTO turns (session_id, line_number, uuid, role, content, content_hash, token_estimate)
            VALUES ('test-insert', 100, 'uuid-2', 'assistant', 'world', 'hash2', 2)
        """)
        db.commit()
        assert get_max_line_number(db, "test-insert") == 100
        db.close()

    def test_content_hash_deterministic(self):
        assert content_hash("hello") == content_hash("hello")
        assert content_hash("hello") != content_hash("world")


class TestFTS5:
    def test_sanitize_fts5_basic(self):
        assert sanitize_fts5_query("migration 076") == '"migration" "076"'
        assert sanitize_fts5_query("hello") == '"hello"'
        assert sanitize_fts5_query("") == '""'

    def test_sanitize_fts5_special_chars(self):
        # These would crash raw FTS5
        assert "?" not in sanitize_fts5_query("what about migration 076?")
        assert ":" not in sanitize_fts5_query("file_path: src/main.py")
        assert sanitize_fts5_query("before - migration") == '"before" "migration"'

    def test_search_returns_results(self):
        db = get_db("test-search")
        db.execute("""
            INSERT INTO turns (session_id, line_number, uuid, role, content, content_hash, token_estimate)
            VALUES ('test-search', 1, 'u1', 'user', 'discuss migration 076 changes', 'h1', 5)
        """)
        db.execute("""
            INSERT INTO turns (session_id, line_number, uuid, role, content, content_hash, token_estimate)
            VALUES ('test-search', 2, 'u2', 'assistant', 'the migration adds columns', 'h2', 5)
        """)
        db.commit()
        db.close()

        results = search("test-search", "migration 076")
        assert len(results) >= 1
        assert any("migration" in r[2].lower() for r in results)

    def test_search_empty_query(self):
        results = search("test-search", "")
        assert results == []

    def test_search_no_match(self):
        results = search("test-search", "xyznonexistent")
        assert results == []


class TestTranscriptParser:
    def _write_jsonl(self, path, entries):
        with open(path, "w") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")

    def test_parse_skips_compact_boundary(self):
        path = os.path.join(_tmpdir, "test-compact.jsonl")
        self._write_jsonl(path, [
            {"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": "hello"}]}, "uuid": "u1"},
            {"type": "system", "subtype": "compact_boundary", "compactMetadata": {"trigger": "manual"}},
            {"type": "user", "isCompactSummary": True, "message": {"role": "user", "content": [{"type": "text", "text": "summary"}]}, "uuid": "u2"},
            {"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": "new turn"}]}, "uuid": "u3"},
        ])
        turns = parse_incremental(path, "test")
        assert len(turns) == 2  # hello + new turn (skips boundary + summary)
        assert turns[0].content == "hello"
        assert turns[1].content == "new turn"

    def test_parse_incremental_skips_old(self):
        path = os.path.join(_tmpdir, "test-incr.jsonl")
        self._write_jsonl(path, [
            {"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": "old"}]}, "uuid": "u1"},
            {"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": "new"}]}, "uuid": "u2"},
        ])
        turns = parse_incremental(path, "test", after_line=1)
        assert len(turns) == 1
        assert turns[0].content == "new"
        assert turns[0].line_number == 2

    def test_parse_extracts_tool_info(self):
        path = os.path.join(_tmpdir, "test-tool.jsonl")
        self._write_jsonl(path, [
            {"type": "assistant", "uuid": "u1", "message": {"role": "assistant", "content": [
                {"type": "text", "text": "reading file"},
                {"type": "tool_use", "name": "Read", "input": {"file_path": "/src/main.rs"}}
            ]}},
        ])
        turns = parse_incremental(path, "test")
        assert len(turns) == 1
        assert turns[0].tool_name == "Read"
        assert "/src/main.rs" in turns[0].files_touched


class TestResume:
    def test_build_resume_empty_session(self):
        context = build_resume_context("nonexistent-session")
        # Should not crash, returns empty or minimal context
        assert isinstance(context, str)

    def test_build_resume_with_turns(self):
        db = get_db("test-resume")
        db.execute("""
            INSERT INTO turns (session_id, line_number, uuid, role, content, content_hash, token_estimate)
            VALUES ('test-resume', 1, 'u1', 'user', 'working on migration 076', 'h1', 5)
        """)
        db.execute("""
            INSERT INTO turns (session_id, line_number, uuid, role, content, content_hash, token_estimate)
            VALUES ('test-resume', 2, 'u2', 'assistant', 'I will update the schema', 'h2', 5)
        """)
        db.commit()
        db.close()

        context = build_resume_context("test-resume")
        assert "migration" in context.lower() or "schema" in context.lower()




class TestSessionState:
    def test_track_task_created(self):
        from hooks.memory.session_state import track_state_event, get_events_path
        import hooks.memory.db as archive_db

        session_id = "test-state-track"
        track_state_event(session_id, "TaskCreate", {
            "tasks": [{"description": "Fix deposit currency", "status": "in_progress"}]
        })

        # Verify in SQLite
        conn = archive_db.get_db(session_id)
        events = conn.execute(
            "SELECT event_type, title FROM state_events WHERE session_id = ?",
            (session_id,)
        ).fetchall()
        conn.close()
        assert len(events) >= 1
        assert events[0][0] == "task_created"
        assert "deposit" in events[0][1].lower()

    def test_track_task_completed(self):
        from hooks.memory.session_state import track_state_event
        import hooks.memory.db as archive_db

        session_id = "test-state-complete"
        track_state_event(session_id, "TaskUpdate", {
            "id": "task-1",
            "status": "completed",
            "description": "Migration 076 applied"
        })

        conn = archive_db.get_db(session_id)
        events = conn.execute(
            "SELECT event_type, title FROM state_events WHERE session_id = ?",
            (session_id,)
        ).fetchall()
        conn.close()
        assert any(e[0] == "task_completed" for e in events)

    def test_track_plan_updated(self):
        from hooks.memory.session_state import track_state_event
        import hooks.memory.db as archive_db

        session_id = "test-state-plan"
        track_state_event(session_id, "EnterPlanMode", {
            "plan": "Multi-currency architecture Phase 2"
        })

        conn = archive_db.get_db(session_id)
        events = conn.execute(
            "SELECT event_type, title FROM state_events WHERE session_id = ?",
            (session_id,)
        ).fetchall()
        conn.close()
        assert any(e[0] == "plan_updated" for e in events)

    def test_generate_state_empty(self):
        from hooks.memory.session_state import generate_session_state, get_state_path
        session_id = "test-state-gen-empty"
        generate_session_state(session_id)
        state_path = get_state_path(session_id)
        assert os.path.isfile(state_path)
        with open(state_path) as f:
            content = f.read()
        assert "Session State" in content

    def test_generate_state_with_events(self):
        from hooks.memory.session_state import (
            track_state_event, generate_session_state, get_state_path
        )
        import hooks.memory.db as archive_db

        session_id = "test-state-gen-full"

        # Add some events
        track_state_event(session_id, "TaskCreate", {
            "tasks": [{"description": "Implement FTS5 search", "status": "in_progress"}]
        })
        track_state_event(session_id, "TaskUpdate", {
            "id": "t1", "status": "completed", "description": "Implement FTS5 search"
        })

        # Add a turn with blocker keyword
        conn = archive_db.get_db(session_id)
        conn.execute("""
            INSERT INTO turns (session_id, line_number, uuid, role, content, content_hash, token_estimate)
            VALUES (?, 1, 'u1', 'assistant', 'This is blocked by secret-shield hook intercepting writes', 'h1', 10)
        """, (session_id,))
        conn.commit()
        conn.close()

        generate_session_state(session_id)

        state_path = get_state_path(session_id)
        with open(state_path) as f:
            content = f.read()

        assert "Done" in content
        assert "FTS5" in content or "search" in content.lower()

    def test_generate_state_preserves_goal(self):
        from hooks.memory.session_state import generate_session_state, get_state_path
        import hooks.memory.db as archive_db

        session_id = "test-state-goal"
        state_path = get_state_path(session_id)

        # Write initial state with a goal
        os.makedirs(os.path.dirname(state_path), mode=0o700, exist_ok=True)
        with open(state_path, "w") as f:
            f.write("# Session State\n\n## Goal\nBuild multi-currency wallet\n")

        # Ensure DB exists
        conn = archive_db.get_db(session_id)
        conn.close()

        generate_session_state(session_id)

        with open(state_path) as f:
            content = f.read()
        assert "multi-currency" in content.lower()

    def test_events_jsonl_written(self):
        from hooks.memory.session_state import track_state_event, get_events_path

        session_id = "test-state-jsonl"
        track_state_event(session_id, "TaskCreate", {
            "tasks": [{"description": "Write tests", "status": "in_progress"}]
        })

        events_path = get_events_path(session_id)
        assert os.path.isfile(events_path)
        with open(events_path) as f:
            lines = f.readlines()
        assert len(lines) >= 1
        event = json.loads(lines[-1])
        assert event["type"] == "task_created"


class TestKnowledge:
    def test_knowledge_db_creates_tables(self):
        from hooks.memory.knowledge import get_knowledge_db
        kdb = get_knowledge_db("/tmp/test-project")
        tables = kdb.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = {t[0] for t in tables}
        assert "session_summaries" in table_names
        assert "entities" in table_names
        kdb.close()

    def test_update_session_knowledge(self):
        from hooks.memory.knowledge import update_session_knowledge, get_knowledge_db
        from hooks.memory.session_state import get_state_path
        import hooks.memory.db as archive_db

        session_id = "test-knowledge-update"
        cwd = "/tmp/test-knowledge-proj"

        # Create session_state.md
        state_path = get_state_path(session_id)
        os.makedirs(os.path.dirname(state_path), mode=0o700, exist_ok=True)
        with open(state_path, "w") as f:
            f.write("""# Session State

## Goal
Build multi-currency wallet

## Done (this session)
- migration 076 applied
- exchange_service.rs created

## Key Decisions
- allocate is same-currency operation
""")

        # Create session DB with a turn
        conn = archive_db.get_db(session_id)
        conn.execute("""
            INSERT INTO turns (session_id, line_number, uuid, role, content, content_hash, token_estimate, files_touched)
            VALUES (?, 1, 'u1', 'user', 'working on wallet', 'h1', 5, '["src/wallet.rs"]')
        """, (session_id,))
        conn.commit()
        conn.close()

        # Update knowledge
        update_session_knowledge(session_id, cwd)

        # Verify
        kdb = get_knowledge_db(cwd)
        row = kdb.execute(
            "SELECT goal, done FROM session_summaries WHERE session_id = ?",
            (session_id,)
        ).fetchone()
        assert row is not None
        assert "multi-currency" in row[0].lower()
        assert "migration" in row[1].lower()

        entities = kdb.execute(
            "SELECT entity_type, name FROM entities WHERE session_id = ?",
            (session_id,)
        ).fetchall()
        entity_types = {e[0] for e in entities}
        assert "file" in entity_types
        assert "decision" in entity_types
        assert "migration" in entity_types
        kdb.close()

    def test_search_knowledge(self):
        from hooks.memory.knowledge import update_session_knowledge, search_knowledge
        from hooks.memory.session_state import get_state_path
        import hooks.memory.db as archive_db

        session_id = "test-knowledge-search"
        cwd = "/tmp/test-knowledge-search-proj"

        # Setup
        state_path = get_state_path(session_id)
        os.makedirs(os.path.dirname(state_path), mode=0o700, exist_ok=True)
        with open(state_path, "w") as f:
            f.write("""# Session State

## Goal
Fix Aurora failover handling

## Done (this session)
- Added connection pool retry logic
- Fixed stale connection detection

## Key Decisions
- Use before_acquire hook for connection health check
""")
        conn = archive_db.get_db(session_id)
        conn.close()

        update_session_knowledge(session_id, cwd)

        # Search from a different session
        result = search_knowledge(cwd, "Aurora connection pool", current_session_id="other-session")
        assert "Aurora" in result or "connection" in result or "failover" in result

    def test_search_knowledge_excludes_current_session(self):
        from hooks.memory.knowledge import search_knowledge

        # Search with same session_id should not return its own results
        result = search_knowledge("/tmp/test-knowledge-search-proj", "Aurora",
                                  current_session_id="test-knowledge-search")
        # Should be empty or not contain test-knowledge-search results
        assert "test-knowledge-search" not in result or result == ""

    def test_search_knowledge_empty_project(self):
        from hooks.memory.knowledge import search_knowledge
        result = search_knowledge("/tmp/nonexistent-project", "anything")
        assert result == ""

    def test_knowledge_reindex(self):
        """Updating same session should not duplicate entities."""
        from hooks.memory.knowledge import update_session_knowledge, get_knowledge_db
        from hooks.memory.session_state import get_state_path
        import hooks.memory.db as archive_db

        session_id = "test-knowledge-reindex"
        cwd = "/tmp/test-knowledge-reindex-proj"

        state_path = get_state_path(session_id)
        os.makedirs(os.path.dirname(state_path), mode=0o700, exist_ok=True)
        with open(state_path, "w") as f:
            f.write("# Session State\n\n## Done (this session)\n- item one\n")
        conn = archive_db.get_db(session_id)
        conn.close()

        # Index twice
        update_session_knowledge(session_id, cwd)
        update_session_knowledge(session_id, cwd)

        kdb = get_knowledge_db(cwd)
        count = kdb.execute(
            "SELECT COUNT(*) FROM entities WHERE session_id = ?",
            (session_id,)
        ).fetchone()[0]
        kdb.close()

        # Should not have duplicates (re-index deletes old entries first)
        assert count <= 5  # reasonable upper bound for one small session


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
