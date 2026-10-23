import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent.core import AgentMode, PentestAgent, ScanState
from agent.scope import ScopePolicy, parse_target
from scan_recovery import ScanRecoveryJournal, default_recovery_root


class ScanRecoveryJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.journal = ScanRecoveryJournal(Path(self.temp.name) / "recovery")
        self.scan_id = "scan_1234567890abcdef"

        async def emit(_event, _data):
            pass

        self.agent = PentestAgent("http://127.0.0.1:1234", "", emit)
        self.agent.state = ScanState(
            target="127.0.0.1", scope="only ports 18080; secret=not-for-disk",
            mode=AgentMode.SUPERVISED, phases=["recon", "web"], is_running=True,
        )
        self.agent.scope_policy = ScopePolicy.from_notes(
            parse_target("http://127.0.0.1:18080/reset?token=not-for-disk"),
            self.agent.state.scope,
        )
        self.agent.state.target_ports = {18080}
        self.agent.state.tool_history = [{
            "tool": "nmap_quick", "target": "127.0.0.1",
            "succeeded": False, "timed_out": True,
            "output": "password=not-for-disk", "observed_ports": [18080],
        }]
        self.agent.state.host_ports["127.0.0.1"] = {18080}

    def test_restart_notice_retains_metadata_but_no_scan_evidence(self):
        self.journal.record(self.scan_id, self.agent)
        saved = self.journal.path.read_text()
        self.assertNotIn("not-for-disk", saved)
        self.assertNotIn("/reset", saved)
        self.assertNotIn("observed_ports", saved)
        self.assertNotIn("18080/tcp", saved)
        self.assertEqual(self.journal.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.journal.root.stat().st_mode & 0o777, 0o700)
        restored = ScanRecoveryJournal(self.journal.root).list_interrupted()
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0]["target"], "http://127.0.0.1:18080")
        self.assertEqual(restored[0]["coverage"], "partial")
        self.assertEqual(restored[0]["completed_ports"], 0)
        self.assertEqual(restored[0]["requested_ports"], 1)
        self.assertEqual(self.journal.list_interrupted({self.scan_id}), [])

    def test_completion_and_explicit_dismissal_clear_notice(self):
        self.journal.record(self.scan_id, self.agent)
        self.journal.remove(self.scan_id)
        self.assertEqual(self.journal.list_interrupted(), [])
        self.journal.record(self.scan_id, self.agent)
        self.agent.state.is_complete = True
        self.agent.state.is_running = False
        self.journal.record(self.scan_id, self.agent)
        self.assertEqual(self.journal.list_interrupted(), [])

    def test_bad_or_expired_data_does_not_become_a_recovery_action(self):
        self.journal._ensure_root()
        self.journal.path.write_text('{"version":1,"entries":[{"scan_id":"scan_bad","target":"--script=bad"}]}')
        self.assertEqual(self.journal.list_interrupted(), [])
        self.journal.path.write_text("x" * 20_000)
        self.assertEqual(self.journal.list_interrupted(), [])

    def test_custom_data_root_permissions_are_not_changed(self):
        broad_root = Path(self.temp.name) / "shared-data-root"
        broad_root.mkdir(mode=0o755)
        with patch.dict("os.environ", {"AEGIS_DATA_DIR": str(broad_root)}):
            journal = ScanRecoveryJournal(default_recovery_root())
            journal.record(self.scan_id, self.agent)
        self.assertEqual(broad_root.stat().st_mode & 0o777, 0o755)
        self.assertEqual(journal.root.stat().st_mode & 0o777, 0o700)
