import hashlib
import io
import json
import os
import struct
import tarfile
import tempfile
import threading
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import AsyncMock, patch

import main
from application import ApplicationResearchService
from application.analyzer import (
    MAX_FINDINGS_PER_RULE_FILE,
    MAX_TEXT_SEGMENT_BYTES,
    AnalysisCancelled,
    analyze_snapshot,
)
from application.intake import IntakeLimitError, IntakeLimits
from application.llm import ApplicationLLMPartialAnswer
from fastapi.testclient import TestClient
from security import AUTH_TOKEN


class ApplicationResearchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.data_root = self.base / "aegis-data"
        self.source_root = self.base / "operator-source"
        self.source_root.mkdir()
        self.service = ApplicationResearchService(self.data_root)

    def tearDown(self):
        self.temporary.cleanup()

    def test_directory_import_is_private_persistent_and_secret_redacted(self):
        fixture_value = "live-value-that-must-never-leak"
        (self.source_root / "package.json").write_text('{"name":"demo"}', encoding="utf-8")
        (self.source_root / "app.py").write_text(
            f'password = "{fixture_value}"\nsubprocess.run(command, shell=True)\n',
            encoding="utf-8",
        )
        (self.source_root / ".env.production").write_text(
            f"API_KEY={fixture_value}\n", encoding="utf-8"
        )
        dependencies = self.source_root / "node_modules"
        dependencies.mkdir()
        (dependencies / "ignored.js").write_text("eval(input)", encoding="utf-8")
        try:
            (self.source_root / "outside-link").symlink_to(self.base / "outside")
        except OSError:
            pass

        imported = self.service.import_path(str(self.source_root))

        self.assertEqual(imported["status"], "imported")
        self.assertEqual(imported["source_type"], "directory")
        self.assertNotIn("artifact_relpath", imported)
        self.assertNotIn("snapshot_relpath", imported)
        self.assertNotIn(str(self.source_root), json.dumps(imported))
        self.assertGreaterEqual(
            imported["intake"]["limits"]["max_directory_bytes"],
            8 * 1024 * 1024 * 1024,
        )
        self.assertGreaterEqual(
            imported["intake"]["limits"]["max_directory_files"],
            100_000,
        )
        warning_reasons = {warning["reason"] for warning in imported["intake"]["warnings"]}
        self.assertIn("generated/dependency directory excluded", warning_reasons)

        analyzed = self.service.analyze_project(imported["id"])

        rule_ids = {finding["rule_id"] for finding in analyzed["findings"]}
        self.assertIn("secret.hardcoded-assignment", rule_ids)
        self.assertIn("secret.environment-value", rule_ids)
        self.assertIn("python.subprocess-shell", rule_ids)
        self.assertNotIn(fixture_value, json.dumps(analyzed))
        self.assertIn("[REDACTED]", json.dumps(analyzed))
        self.assertTrue(all(finding["status"] == "static_evidence" for finding in analyzed["findings"]))
        self.assertTrue(all(finding["has_private_evidence"] for finding in analyzed["findings"]))
        self.assertFalse(analyzed["summary"]["artifact_executed"])
        self.assertTrue((self.source_root / "app.py").exists())

        secret_finding = next(
            finding for finding in analyzed["findings"]
            if finding["rule_id"] == "secret.environment-value"
        )
        private = self.service.get_private_finding(
            imported["id"], secret_finding["id"]
        )
        self.assertIn(fixture_value, private["raw_evidence"])
        exported = self.service.private_evidence_export(imported["id"])
        self.assertIn(fixture_value, json.dumps(exported))

        restarted = ApplicationResearchService(self.data_root)
        persisted = restarted.get_project(imported["id"])
        self.assertEqual(persisted["status"], "complete")
        self.assertEqual(len(persisted["findings"]), len(analyzed["findings"]))
        persisted_private = restarted.get_private_finding(
            imported["id"], secret_finding["id"]
        )
        self.assertIn(fixture_value, persisted_private["raw_evidence"])

    def test_private_key_vault_retains_complete_bounded_pem_block(self):
        key_body = "fixture-key-body-that-is-not-real"
        key = self.source_root / "deployment-key.pem"
        key.write_text(
            "-----BEGIN PRIVATE KEY-----\n"
            f"{key_body}\n"
            "-----END PRIVATE KEY-----\n",
            encoding="utf-8",
        )

        imported = self.service.import_path(str(key))
        analyzed = self.service.analyze_project(imported["id"])
        finding = next(
            item for item in analyzed["findings"]
            if item["rule_id"] == "secret.private-key"
        )

        self.assertNotIn(key_body, json.dumps(analyzed))
        self.assertEqual(finding["evidence"], "[REDACTED PRIVATE KEY MARKER]")
        private = self.service.get_private_finding(imported["id"], finding["id"])
        self.assertIn(key_body, private["raw_evidence"])
        self.assertIn("-----END PRIVATE KEY-----", private["raw_evidence"])

    def test_long_line_boundary_and_crlf_keep_correct_line_numbers(self):
        marker = "AEGIS{CROSSES_STREAM_BOUNDARY_71C9}"
        source = self.source_root / "segmented.txt"
        source.write_bytes(
            b"X" * (MAX_TEXT_SEGMENT_BYTES - 7) + b" "
            + marker.encode() + b"\r\n"
            + b"AEGIS{SECOND_CRLF_LINE_44228}\r\n"
        )
        imported = self.service.import_path(str(source))
        analyzed = self.service.analyze_project(imported["id"])
        flags = [
            item for item in analyzed["findings"]
            if item["rule_id"] == "evidence.scoring-flag"
        ]
        self.assertEqual({item["line"] for item in flags}, {1, 2})
        self.assertEqual(analyzed["summary"]["inventory"]["segmented_long_lines"], 1)
        self.assertTrue(analyzed["summary"]["coverage_incomplete"])
        self.assertNotIn(marker, json.dumps(analyzed))
        first = next(item for item in flags if item["line"] == 1)
        self.assertIn(marker, self.service.get_private_finding(imported["id"], first["id"])["raw_evidence"])

    def test_large_source_is_scanned_through_end_without_loading_whole_file(self):
        filler = "# ordinary source line\n" * 75_000
        middle_marker = "AEGIS{LARGE_FILE_MIDDLE_MARKER_284D}"
        marker = "AEGIS{LARGE_FILE_END_MARKER_48D7}"
        source = self.source_root / "large.py"
        source.write_text(
            "AEGIS{LARGE_FILE_START_MARKER_01A2}\n"
            + filler
            + middle_marker + "\n"
            + filler
            + "-----BEGIN PRIVATE KEY-----\n"
            + "synthetic-large-key-body\n"
            + "-----END PRIVATE KEY-----\n"
            + marker + "\n",
            encoding="utf-8",
        )
        self.assertGreater(source.stat().st_size, 3 * 1024 * 1024)

        imported = self.service.import_path(str(source))
        analyzed = self.service.analyze_project(imported["id"])
        flags = [item for item in analyzed["findings"] if item["rule_id"] == "evidence.scoring-flag"]
        self.assertEqual([item["line"] for item in flags], [1, 75_002, 150_006])
        self.assertEqual(analyzed["summary"]["inventory"]["analyzed_text_bytes"], source.stat().st_size)
        self.assertEqual(analyzed["summary"]["inventory"]["skipped_large_text_candidates"], 0)
        key = next(item for item in analyzed["findings"] if item["rule_id"] == "secret.private-key")
        private = self.service.get_private_finding(imported["id"], key["id"])
        self.assertIn("synthetic-large-key-body", private["raw_evidence"])
        self.assertIn("-----END PRIVATE KEY-----", private["raw_evidence"])

    def test_cancelled_rerun_preserves_last_complete_findings(self):
        (self.source_root / "flags.txt").write_text(
            "AEGIS{PRESERVED_AFTER_CANCEL_4192}\n", encoding="utf-8"
        )
        imported = self.service.import_path(str(self.source_root))
        original = self.service.analyze_project(imported["id"])
        started = threading.Event()
        release = threading.Event()
        errors: list[BaseException] = []

        def paused_scan(*args, **kwargs):
            real_progress = kwargs["progress"]

            def pause_once(value):
                real_progress(value)
                if not started.is_set():
                    started.set()
                    self.assertTrue(release.wait(5), "test scan did not resume")

            kwargs["progress"] = pause_once
            return analyze_snapshot(*args, **kwargs)

        def run_again():
            try:
                self.service.analyze_project(imported["id"])
            except BaseException as exc:
                errors.append(exc)

        with patch("application.service.analyze_snapshot", side_effect=paused_scan):
            worker = threading.Thread(target=run_again)
            worker.start()
            try:
                self.assertTrue(started.wait(5), "analysis did not report progress")
                job = self.service.get_analysis_job(imported["id"])
                self.assertEqual(job["status"], "running")
                self.assertGreaterEqual(job["progress"]["files_visited"], 1)
                requested = self.service.cancel_analysis(imported["id"])
                self.assertTrue(requested["progress"]["cancel_requested"])
                self.service.store.update_job_progress(
                    job["id"], imported["id"], {"phase": "quick_static", "files_visited": 2}
                )
                self.assertTrue(
                    self.service.get_analysis_job(imported["id"])["progress"]["cancel_requested"]
                )
            finally:
                release.set()
                worker.join(5)

        self.assertFalse(worker.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], AnalysisCancelled)
        self.assertEqual(self.service.get_analysis_job(imported["id"])["status"], "cancelled")
        preserved = self.service.get_project(imported["id"])
        self.assertEqual(preserved["status"], "complete")
        self.assertEqual(preserved["findings"], original["findings"])

    def test_more_than_500_findings_are_saved_and_read_in_pages(self):
        for file_index in range(9):
            (self.source_root / f"part-{file_index:02d}.txt").write_text(
                "\n".join(
                    f"AEGIS{{PAGED_{file_index:02d}_{line_index:02d}_71A5}}"
                    for line_index in range(60)
                ) + "\n",
                encoding="utf-8",
            )

        imported = self.service.import_path(str(self.source_root))
        analyzed = self.service.analyze_project(imported["id"])
        self.assertEqual(analyzed["findings_total"], 540)
        self.assertEqual(len(analyzed["findings"]), 100)
        self.assertFalse(analyzed["summary"]["findings_truncated"])
        ids = set()
        for offset in range(0, 540, 100):
            page = self.service.list_findings_page(imported["id"], offset, 100)
            self.assertEqual(page["total"], 540)
            self.assertEqual(page["analysis_job_id"], analyzed["summary"]["analysis_job_id"])
            ids.update(item["id"] for item in page["findings"])
        self.assertEqual(len(ids), 540)
        with ThreadPoolExecutor(max_workers=6) as workers:
            concurrent_pages = list(workers.map(
                lambda offset: self.service.list_findings_page(imported["id"], offset, 100),
                range(0, 540, 100),
            ))
        self.assertEqual(
            {item["id"] for page in concurrent_pages for item in page["findings"]},
            ids,
        )
        private_page = self.service.private_evidence_page(imported["id"], 500, 100)
        self.assertEqual(private_page["total"], 540)
        self.assertEqual(private_page["project"]["analysis_job_id"], analyzed["summary"]["analysis_job_id"])
        self.assertEqual(len(private_page["evidence"]), 40)
        self.assertNotIn("AEGIS{PAGED_08_59_71A5}", json.dumps(analyzed))

    def test_private_model_retrieval_ranks_late_requested_flag_without_loading_all(self):
        for file_index in range(9):
            (self.source_root / f"secret-{file_index:02d}.py").write_text(
                "\n".join(
                    f'password = "synthetic-{file_index:02d}-{line_index:02d}-value"'
                    for line_index in range(60)
                ) + "\n",
                encoding="utf-8",
            )
        marker = "AEGIS{LATE_FLAG_AFTER_540_SECRETS}"
        (self.source_root / "late-flag.txt").write_text(marker + "\n", encoding="utf-8")
        imported = self.service.import_path(str(self.source_root))
        analyzed = self.service.analyze_project(imported["id"])
        self.assertEqual(analyzed["findings_total"], 541)
        default_page = self.service.private_evidence_page(imported["id"], 0, 500)
        self.assertNotIn(marker, json.dumps(default_page))

        selected = self.service.store.list_private_evidence_for_model(
            imported["id"], "What is the exact flag?", 500
        )
        self.assertEqual(selected["total"], 541)
        self.assertEqual(len(selected["evidence"]), 500)
        self.assertIn(marker, selected["evidence"][0]["raw_evidence"])
        self.assertTrue(selected["has_more"])

    def test_extracts_flags_operational_context_and_uri_credentials_without_exec_false_positive(self):
        (self.source_root / "flags.txt").write_text(
            "AEGIS{STATIC_DISCOVERY_71C9}\n"
            "AEGIS{VERSION_CORRELATION_44228}\n"
            "AEGIS{CREDENTIAL_CHAIN_90AF}\n",
            encoding="utf-8",
        )
        (self.source_root / "operations-notes.txt").write_text(
            "Emergency administrator: research-admin\n"
            "Temporary password: GlacierConsole-71!\n"
            "Backup service account: svc_borealis_backup\n"
            "Backup password: AuroraColdStore-58!\n"
            "Internal project codename: NIGHTJAR\n"
            "Confidential acquisition target: Example Meridian Labs\n"
            "Recovery phrase: north-star frozen-river glass-orbit\n",
            encoding="utf-8",
        )
        (self.source_root / "config.js").write_text(
            'const database = "postgres://vault_admin:PolarLedger-63!@db.example.internal:5432/vault";\n'
            'const adminPanel = "https://admin.example.internal";\n'
            'const signing = "https://signing.example.internal/v1";\n',
            encoding="utf-8",
        )
        (self.source_root / "electron-main.js").write_text(
            'child_process.exec("fixture " + untrusted);\n'
            "eval(untrustedPolicy);\n",
            encoding="utf-8",
        )

        imported = self.service.import_path(str(self.source_root))
        analyzed = self.service.analyze_project(imported["id"])
        by_rule: dict[str, list[dict]] = {}
        for finding in analyzed["findings"]:
            by_rule.setdefault(finding["rule_id"], []).append(finding)

        self.assertEqual(len(by_rule["evidence.scoring-flag"]), 3)
        self.assertEqual(len(by_rule["secret.labeled-value"]), 3)
        self.assertEqual(len(by_rule["identity.account-identifier"]), 2)
        self.assertEqual(len(by_rule["intelligence.context-identifier"]), 2)
        self.assertEqual(len(by_rule["secret.connection-uri-credentials"]), 1)
        self.assertGreaterEqual(len(by_rule["network.internal-endpoint"]), 3)
        self.assertEqual(len(by_rule["node.child-process-exec"]), 1)
        self.assertEqual(len(by_rule["code.dynamic-eval"]), 1)
        self.assertIn("eval(untrustedPolicy)", by_rule["code.dynamic-eval"][0]["evidence"])

        public_record = json.dumps(analyzed)
        for exact_value in (
            "AEGIS{STATIC_DISCOVERY_71C9}",
            "research-admin",
            "GlacierConsole-71!",
            "PolarLedger-63!",
            "db.example.internal",
            "NIGHTJAR",
            "Example Meridian Labs",
        ):
            self.assertNotIn(exact_value, public_record)

        private_record = json.dumps(
            self.service.private_evidence_export(imported["id"])
        )
        for exact_value in (
            "AEGIS{STATIC_DISCOVERY_71C9}",
            "AEGIS{VERSION_CORRELATION_44228}",
            "AEGIS{CREDENTIAL_CHAIN_90AF}",
            "research-admin",
            "svc_borealis_backup",
            "GlacierConsole-71!",
            "AuroraColdStore-58!",
            "north-star frozen-river glass-orbit",
            "PolarLedger-63!",
            "NIGHTJAR",
            "Example Meridian Labs",
            "admin.example.internal",
            "signing.example.internal",
        ):
            self.assertIn(exact_value, private_record)

        inventory = analyzed["summary"]["inventory"]
        self.assertEqual(inventory["files"], 4)
        self.assertEqual(inventory["analyzed_text_files"], 4)
        self.assertEqual(inventory["skipped_large_text_candidates"], 0)
        self.assertGreater(analyzed["summary"]["rule_evaluations"], 0)

    def test_per_file_finding_cap_reports_confirmed_omissions(self):
        flags = [
            f"AEGIS{{SYNTHETIC_COVERAGE_{index:02d}}}"
            for index in range(MAX_FINDINGS_PER_RULE_FILE + 3)
        ]
        (self.source_root / "flags.txt").write_text(
            "\n".join(flags) + "\n", encoding="utf-8"
        )

        imported = self.service.import_path(str(self.source_root))
        analyzed = self.service.analyze_project(imported["id"])
        flag_findings = [
            item for item in analyzed["findings"]
            if item["rule_id"] == "evidence.scoring-flag"
        ]

        self.assertEqual(len(flag_findings), MAX_FINDINGS_PER_RULE_FILE)
        self.assertTrue(analyzed["summary"]["findings_truncated"])
        self.assertGreaterEqual(analyzed["summary"]["findings_omitted_lower_bound"], 1)
        self.assertEqual(analyzed["summary"]["per_rule_file_omission_count"], 1)
        self.assertFalse(analyzed["summary"]["artifact_executed"])
        self.assertNotIn(flags[-1], json.dumps(analyzed))

    def test_exact_per_file_finding_cap_is_not_reported_as_omission(self):
        (self.source_root / "flags.txt").write_text(
            "\n".join(
                f"AEGIS{{SYNTHETIC_EXACT_LIMIT_{index:02d}}}"
                for index in range(MAX_FINDINGS_PER_RULE_FILE)
            ) + "\n",
            encoding="utf-8",
        )

        imported = self.service.import_path(str(self.source_root))
        analyzed = self.service.analyze_project(imported["id"])

        self.assertEqual(
            sum(item["rule_id"] == "evidence.scoring-flag" for item in analyzed["findings"]),
            MAX_FINDINGS_PER_RULE_FILE,
        )
        self.assertFalse(analyzed["summary"]["findings_truncated"])
        self.assertEqual(analyzed["summary"]["findings_omitted_lower_bound"], 0)

    def test_unrelated_object_exec_is_not_reported_as_node_shell_execution(self):
        (self.source_root / "queries.js").write_text(
            'db.exec("SELECT 1");\n'
            'child_process.exec("echo synthetic");\n',
            encoding="utf-8",
        )

        imported = self.service.import_path(str(self.source_root))
        analyzed = self.service.analyze_project(imported["id"])
        shell_findings = [
            item for item in analyzed["findings"]
            if item["rule_id"] == "node.child-process-exec"
        ]

        self.assertEqual(len(shell_findings), 1)
        self.assertEqual(shell_findings[0]["line"], 2)

    def test_project_deletion_removes_only_aegis_copy_and_persisted_evidence(self):
        fixture = self.source_root / ".env.local"
        fixture.write_text("API_KEY=delete-test-secret\n", encoding="utf-8")
        imported = self.service.import_path(str(fixture))
        analyzed = self.service.analyze_project(imported["id"])
        project_directory = self.service.store.project_directory(imported["id"])

        self.assertTrue(project_directory.exists())
        self.assertTrue(analyzed["findings"])

        result = self.service.delete_project(imported["id"])

        self.assertTrue(result["deleted"])
        self.assertFalse(result["cleanup_pending"])
        self.assertFalse(project_directory.exists())
        self.assertTrue(fixture.exists())
        self.assertEqual(self.service.list_projects(), [])
        with self.assertRaises(KeyError):
            self.service.get_project(imported["id"])

    def test_zip_extraction_skips_traversal_symlinks_and_duplicate_paths(self):
        archive = self.source_root / "sample.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as container:
            container.writestr("src/app.py", "eval(user_input)\n")
            container.writestr("../escape.py", "should_not_escape = True\n")
            container.writestr("SRC/APP.PY", "duplicate_on_case_insensitive_filesystems = True\n")
            symlink = zipfile.ZipInfo("src/link")
            symlink.create_system = 3
            symlink.external_attr = (0o120777 << 16)
            container.writestr(symlink, "../../outside")

        imported = self.service.import_path(str(archive))
        internal = self.service.store.get_internal_project(imported["id"])
        project_directory = self.service.store.project_directory(imported["id"])
        snapshot = project_directory / internal["snapshot_relpath"]

        self.assertTrue((snapshot / "src" / "app.py").is_file())
        self.assertFalse((project_directory / "escape.py").exists())
        self.assertFalse((snapshot / "src" / "link").exists())
        reasons = {warning["reason"] for warning in imported["intake"]["warnings"]}
        self.assertIn("path rejected", reasons)
        self.assertIn("duplicate path skipped", reasons)
        self.assertIn("symbolic link skipped", reasons)

    def test_archive_quota_failure_removes_only_generated_project(self):
        archive = self.source_root / "oversize.zip"
        with zipfile.ZipFile(archive, "w") as container:
            container.writestr("large.txt", "12345")
        limited = ApplicationResearchService(
            self.data_root / "limited",
            limits=IntakeLimits(max_archive_entry_bytes=4),
        )

        with self.assertRaises(IntakeLimitError):
            limited.import_path(str(archive))

        self.assertTrue(archive.exists())
        self.assertEqual(list(limited.store.projects_root.iterdir()), [])

    def test_binary_magic_is_inventoried_without_execution(self):
        executable = self.source_root / "program.bin"
        executable.write_bytes(b"MZ" + b"\x00" * 64)

        imported = self.service.import_path(str(executable))
        analyzed = self.service.analyze_project(imported["id"])

        self.assertEqual(imported["artifact_kind"], "windows_binary")
        self.assertEqual(analyzed["summary"]["inventory"]["formats"]["PE"], 1)
        self.assertEqual(analyzed["findings"], [])
        self.assertFalse(analyzed["summary"]["artifact_executed"])

    def test_cisco_ios_xe_image_is_recognized_and_firmware_inventoried(self):
        image = self.source_root / "cat9k_iosxe.17.12.04.SPA.bin"
        payload = (
            b"Cisco IOS XE Software, Version 17.12.04\n"
            b"\x00" * 64
            + b"hsqs"
            + b"\x00" * 64
        )
        image.write_bytes(payload)

        imported = self.service.import_path(str(image))
        analyzed = self.service.analyze_project(imported["id"])
        firmware = analyzed["summary"]["firmware"]

        self.assertEqual(imported["artifact_kind"], "cisco_ios_firmware")
        self.assertEqual(firmware["vendor"], "Cisco")
        self.assertEqual(firmware["platform_family"], "Cisco IOS XE")
        self.assertIn("17.12.04", firmware["versions"])
        self.assertIn("SquashFS filesystem", firmware["embedded_formats"])
        self.assertEqual(firmware["binary_scan_coverage"], "complete")
        self.assertEqual(firmware["authenticity"], "not_verified_offline")
        self.assertFalse(firmware["advisory_lookup_performed"])
        self.assertFalse(firmware["signature_verification_performed"])
        self.assertFalse(firmware["artifact_executed"])
        self.assertEqual(
            firmware["images"][0]["sha256"], hashlib.sha256(payload).hexdigest()
        )

    def test_cisco_advisory_results_are_preserved_across_deep_reanalysis(self):
        image = self.source_root / "cat9k_iosxe.17.12.04.SPA.bin"
        image.write_bytes(b"Cisco IOS XE Software, Version 17.12.04\n")
        imported = self.service.import_path(str(image))
        self.service.analyze_project(imported["id"])
        lookup = {
            "status": "complete",
            "source": "Cisco PSIRT openVuln API",
            "version": "17.12.04",
            "os_type": "iosxe",
            "advisory_count": 1,
            "advisories": [{"advisory_id": "cisco-sa-test"}],
            "access_token_stored": False,
        }

        updated = self.service.record_firmware_advisory_lookup(
            imported["id"], lookup
        )
        self.assertTrue(updated["summary"]["firmware"]["advisory_lookup_performed"])
        self.assertNotIn("synthetic-token-value", json.dumps(updated))
        self.assertFalse(
            updated["summary"]["firmware"]["advisory_lookup"][
                "access_token_stored"
            ]
        )

        reanalyzed = self.service.analyze_project(imported["id"], "deep_firmware")
        firmware = reanalyzed["summary"]["firmware"]
        self.assertEqual(firmware["advisory_lookup"], lookup)
        self.assertTrue(firmware["advisory_lookup_performed"])

    def test_cisco_tar_bundle_is_safely_extracted_and_links_are_skipped(self):
        archive = self.source_root / "c3750-ipservicesk9-tar.122-55.SE12.tar"
        image_payload = b"Cisco IOS Software, C3750 Software, Version 15.2(4)E\n"
        with tarfile.open(archive, "w") as container:
            image = tarfile.TarInfo(
                "update/c3750-ipservicesk9-mz.152-4.E.bin"
            )
            image.size = len(image_payload)
            container.addfile(image, io.BytesIO(image_payload))

            provisioning_payload = (
                b"pkginfo: packages.conf\n"
                b"pkginfo: update/c3750-rpbase.15.2.04.SPA.pkg\n"
            )
            provisioning = tarfile.TarInfo("update/packages.conf")
            provisioning.size = len(provisioning_payload)
            container.addfile(provisioning, io.BytesIO(provisioning_payload))

            traversal_payload = b"must not escape"
            traversal = tarfile.TarInfo("../escape.txt")
            traversal.size = len(traversal_payload)
            container.addfile(traversal, io.BytesIO(traversal_payload))

            link = tarfile.TarInfo("update/outside-link")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../outside"
            container.addfile(link)

        imported = self.service.import_path(str(archive))
        internal = self.service.store.get_internal_project(imported["id"])
        project_directory = self.service.store.project_directory(imported["id"])
        snapshot = project_directory / internal["snapshot_relpath"]

        self.assertEqual(imported["artifact_kind"], "cisco_ios_firmware_bundle")
        self.assertEqual(imported["intake"]["extracted_files"], 2)
        self.assertTrue(
            (snapshot / "update" / "c3750-ipservicesk9-mz.152-4.E.bin").is_file()
        )
        self.assertFalse((project_directory / "escape.txt").exists())
        self.assertFalse((snapshot / "update" / "outside-link").exists())
        warning_reasons = {
            warning["reason"] for warning in imported["intake"]["warnings"]
        }
        self.assertIn("path rejected", warning_reasons)
        self.assertIn("symbolic or hard link skipped", warning_reasons)

        analyzed = self.service.analyze_project(imported["id"])
        firmware = analyzed["summary"]["firmware"]
        self.assertEqual(firmware["vendor"], "Cisco")
        self.assertIn("15.2(4)E", firmware["versions"])
        self.assertGreaterEqual(firmware["candidate_files"], 2)
        self.assertEqual(
            firmware["missing_package_references"],
            ["update/c3750-rpbase.15.2.04.SPA.pkg"],
        )

    def test_deep_firmware_analysis_finds_redacted_config_and_elf_hardening(self):
        image = self.source_root / "cat9k_iosxe.17.12.04.SPA.bin"
        elf_ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\x00" * 7
        elf_header = struct.pack(
            "<HHIQQQIHHHHHH",
            2,
            62,
            1,
            0,
            64,
            0,
            0,
            64,
            56,
            1,
            0,
            0,
            0,
        )
        executable_stack = struct.pack(
            "<IIQQQQQQ",
            0x6474E551,
            0x7,
            0,
            0,
            0,
            0,
            0,
            16,
        )
        fixture_value = "FirmwareOnlySyntheticSecret"
        payload = (
            b"Cisco IOS XE Software, Version 17.12.04\n\x00"
            b"OpenSSL 1.1.1k\n"
            + f"username admin password 0 {fixture_value}\n".encode()
            + b"snmp-server community public RO\n"
            + b"-----BEGIN PRIVATE KEY-----\nsynthetic-not-a-real-key\n"
            + b"-----END PRIVATE KEY-----\n\x00"
            + elf_ident
            + elf_header
            + executable_stack
        )
        image.write_bytes(payload)

        imported = self.service.import_path(str(image))
        analyzed = self.service.analyze_project(imported["id"], "deep_firmware")
        firmware = analyzed["summary"]["firmware"]
        deep = firmware["deep_analysis"]
        rule_ids = {finding["rule_id"] for finding in analyzed["findings"]}

        self.assertEqual(analyzed["summary"]["analysis_profile"], "deep_firmware_static")
        self.assertIn("cisco.config-plaintext-password", rule_ids)
        self.assertIn("cisco.config-default-snmp-community", rule_ids)
        self.assertIn("firmware.private-key", rule_ids)
        self.assertIn("firmware.elf-executable-stack", rule_ids)
        self.assertIn("firmware.elf-non-pie", rule_ids)
        self.assertNotIn(fixture_value, json.dumps(analyzed))
        self.assertIn("[REDACTED]", json.dumps(analyzed))
        self.assertIn(
            {"name": "OpenSSL", "version": "1.1.1k"},
            [
                {"name": item["name"], "version": item["version"]}
                for item in deep["components"]
            ],
        )
        self.assertEqual(deep["elf_objects"][0]["machine"], "x86-64")
        self.assertTrue(deep["elf_objects"][0]["stack_executable"])

        credential_finding = next(
            finding for finding in analyzed["findings"]
            if finding["rule_id"] == "cisco.config-plaintext-password"
        )
        private = self.service.get_private_finding(
            imported["id"], credential_finding["id"]
        )
        self.assertIn(fixture_value, private["raw_evidence"])

    def test_cisco_configuration_rules_redact_credentials_in_text_exports(self):
        config = self.source_root / "startup.cfg"
        fixture_value = "ConfigOnlySyntheticSecret"
        config.write_text(
            f"username operator password 0 {fixture_value}\n"
            "transport input ssh telnet\n"
            "ip ssh version 1\n",
            encoding="utf-8",
        )

        imported = self.service.import_path(str(config))
        analyzed = self.service.analyze_project(imported["id"])
        rule_ids = {finding["rule_id"] for finding in analyzed["findings"]}

        self.assertIn("cisco.config-plaintext-password", rule_ids)
        self.assertIn("cisco.config-telnet-vty", rule_ids)
        self.assertIn("cisco.config-ssh-v1", rule_ids)
        self.assertNotIn(fixture_value, json.dumps(analyzed))
        self.assertIn("[REDACTED]", json.dumps(analyzed))

    def test_tar_quota_failure_removes_only_generated_project(self):
        archive = self.source_root / "oversize.tar"
        with tarfile.open(archive, "w") as container:
            payload = b"12345"
            member = tarfile.TarInfo("large.bin")
            member.size = len(payload)
            container.addfile(member, io.BytesIO(payload))
        limited = ApplicationResearchService(
            self.data_root / "limited-tar",
            limits=IntakeLimits(max_archive_entry_bytes=4),
        )

        with self.assertRaises(IntakeLimitError):
            limited.import_path(str(archive))

        self.assertTrue(archive.exists())
        self.assertEqual(list(limited.store.projects_root.iterdir()), [])

    def test_rule_definition_text_is_not_mistaken_for_dynamic_evaluation(self):
        (self.source_root / "scanner.py").write_text(
            'pattern = re.compile(r"eval\\s*\\(")\n', encoding="utf-8"
        )

        imported = self.service.import_path(str(self.source_root))
        analyzed = self.service.analyze_project(imported["id"])

        self.assertNotIn(
            "code.dynamic-eval",
            {finding["rule_id"] for finding in analyzed["findings"]},
        )


class ApplicationApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.source = self.base / "source.py"
        self.source.write_text("eval(untrusted)\n", encoding="utf-8")
        self.secret_source = self.base / ".env.production"
        self.fixture_value = "synthetic-api-secret-value"
        self.secret_source.write_text(
            f"API_KEY={self.fixture_value}\n", encoding="utf-8"
        )
        self.previous_service = main._application_service
        main._application_service = ApplicationResearchService(self.base / "api-data")
        self.client = TestClient(main.app)
        self.headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}

    def tearDown(self):
        main._application_service = self.previous_service
        self.client.close()
        self.temporary.cleanup()

    def test_authenticated_import_analyze_and_list_round_trip(self):
        with patch.dict(os.environ, {"AEGIS_ARTIFACT_IMPORT_TOKEN": "picker-secret"}):
            denied = self.client.post(
                "/api/application/import",
                headers=self.headers,
                json={"path": str(self.source)},
            )
            self.assertEqual(denied.status_code, 403)

            response = self.client.post(
                "/api/application/import",
                headers={**self.headers, "X-AEGIS-Artifact-Token": "picker-secret"},
                json={"path": str(self.source)},
            )
        self.assertEqual(response.status_code, 200)
        project_id = response.json()["id"]

        analysis = self.client.post(
            f"/api/application/projects/{project_id}/analyze",
            headers=self.headers,
        )
        self.assertEqual(analysis.status_code, 200)
        self.assertEqual(analysis.json()["findings"][0]["rule_id"], "code.dynamic-eval")

        listing = self.client.get("/api/application/projects", headers=self.headers)
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.json()["projects"][0]["id"], project_id)

    def test_cisco_advisory_lookup_uses_detected_version_and_stores_no_token(self):
        firmware_source = self.base / "cat9k_iosxe.17.12.04.SPA.bin"
        firmware_source.write_bytes(
            b"Cisco IOS XE Software, Version 17.12.04\n"
        )
        imported = self.client.post(
            "/api/application/import",
            headers=self.headers,
            json={"path": str(firmware_source)},
        )
        self.assertEqual(imported.status_code, 200)
        project_id = imported.json()["id"]
        analyzed = self.client.post(
            f"/api/application/projects/{project_id}/analyze",
            headers=self.headers,
        )
        self.assertEqual(analyzed.status_code, 200)

        malformed_value = "short-unique-secret"
        malformed = self.client.post(
            f"/api/application/projects/{project_id}/cisco-advisories",
            headers=self.headers,
            json={"access_token": malformed_value, "version": "17.12.04"},
        )
        self.assertEqual(malformed.status_code, 400)
        self.assertNotIn(malformed_value, malformed.text)

        fixture_access_value = "synthetic-token-value-1234567890"
        lookup = {
            "status": "complete",
            "source": "Cisco PSIRT openVuln API",
            "version": "17.12.04",
            "os_type": "iosxe",
            "advisory_count": 0,
            "advisories": [],
            "access_token_stored": False,
        }
        psirt = AsyncMock(return_value=lookup)
        with patch("main.fetch_cisco_advisories", psirt):
            response = self.client.post(
                f"/api/application/projects/{project_id}/cisco-advisories",
                headers=self.headers,
                json={
                    "access_token": fixture_access_value,
                    "version": "17.12.04",
                },
            )

        self.assertEqual(response.status_code, 200)
        psirt.assert_awaited_once_with(
            access_token=fixture_access_value,
            version="17.12.04",
            os_type="iosxe",
        )
        self.assertNotIn(fixture_access_value, response.text)
        firmware = response.json()["summary"]["firmware"]
        self.assertTrue(firmware["advisory_lookup_performed"])
        self.assertEqual(firmware["advisory_lookup"], lookup)

    def test_api_never_returns_original_path(self):
        response = self.client.post(
            "/api/application/import",
            headers=self.headers,
            json={"path": str(self.source)},
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(str(self.base), response.text)

    def _import_and_analyze_secret(self, token: str) -> tuple[str, str]:
        response = self.client.post(
            "/api/application/import",
            headers={**self.headers, "X-AEGIS-Artifact-Token": token},
            json={"path": str(self.secret_source)},
        )
        self.assertEqual(response.status_code, 200)
        project_id = response.json()["id"]
        analysis = self.client.post(
            f"/api/application/projects/{project_id}/analyze",
            headers=self.headers,
        )
        self.assertEqual(analysis.status_code, 200)
        self.assertNotIn(self.fixture_value, analysis.text)
        return project_id, analysis.json()["findings"][0]["id"]

    def test_private_evidence_requires_desktop_token_and_exact_membership(self):
        with patch.dict(os.environ, {"AEGIS_ARTIFACT_IMPORT_TOKEN": "picker-secret"}):
            project_id, finding_id = self._import_and_analyze_secret("picker-secret")
            endpoint = (
                f"/api/application/projects/{project_id}/findings/"
                f"{finding_id}/private-evidence"
            )
            denied = self.client.get(endpoint, headers=self.headers)
            self.assertEqual(denied.status_code, 403)
            revealed = self.client.get(
                endpoint,
                headers={
                    **self.headers,
                    "X-AEGIS-Artifact-Token": "picker-secret",
                },
            )
            self.assertEqual(revealed.status_code, 200)
            self.assertIn(self.fixture_value, revealed.json()["raw_evidence"])

            other_id = "appf_" + "0" * 20
            wrong_finding = self.client.get(
                f"/api/application/projects/{project_id}/findings/{other_id}/private-evidence",
                headers={
                    **self.headers,
                    "X-AEGIS-Artifact-Token": "picker-secret",
                },
            )
            self.assertEqual(wrong_finding.status_code, 404)

    def test_findings_pages_are_authenticated_and_private_pages_require_desktop_token(self):
        with patch.dict(os.environ, {"AEGIS_ARTIFACT_IMPORT_TOKEN": "picker-secret"}):
            project_id, _ = self._import_and_analyze_secret("picker-secret")
            public_path = f"/api/application/projects/{project_id}/findings?offset=0&limit=1"
            self.assertEqual(self.client.get(public_path).status_code, 401)
            public = self.client.get(public_path, headers=self.headers)
            self.assertEqual(public.status_code, 200)
            self.assertEqual(public.json()["total"], 1)
            self.assertNotIn(self.fixture_value, public.text)
            self.assertEqual(
                self.client.get(
                    f"/api/application/projects/{project_id}/findings?offset=-1&limit=1",
                    headers=self.headers,
                ).status_code,
                400,
            )

            private_path = f"/api/application/projects/{project_id}/private-evidence/page?offset=0&limit=1"
            self.assertEqual(self.client.get(private_path, headers=self.headers).status_code, 403)
            private = self.client.get(
                private_path,
                headers={**self.headers, "X-AEGIS-Artifact-Token": "picker-secret"},
            )
            self.assertEqual(private.status_code, 200)
            self.assertEqual(private.json()["total"], 1)
            self.assertIn(self.fixture_value, private.text)

    def test_private_export_and_llm_context_are_explicitly_gated(self):
        with patch.dict(os.environ, {"AEGIS_ARTIFACT_IMPORT_TOKEN": "picker-secret"}):
            project_id, _finding_id = self._import_and_analyze_secret("picker-secret")
            export_path = (
                f"/api/application/projects/{project_id}/private-evidence/export"
            )
            denied_export = self.client.get(export_path, headers=self.headers)
            self.assertEqual(denied_export.status_code, 403)
            private_export = self.client.get(
                export_path,
                headers={
                    **self.headers,
                    "X-AEGIS-Artifact-Token": "picker-secret",
                },
            )
            self.assertEqual(private_export.status_code, 200)
            self.assertIn(self.fixture_value, private_export.text)

            analyst = AsyncMock(return_value="Grounded fixture answer")
            prepare_model = AsyncMock(return_value=None)
            with (
                patch("main._prepare_application_llm", prepare_model),
                patch("main.ask_application_llm", analyst),
            ):
                public_chat = self.client.post(
                    f"/api/application/projects/{project_id}/chat",
                    headers=self.headers,
                    json={
                        "question": "What was found?",
                        "lm_url": "http://localhost:1234",
                        "model": "qwen/qwen3.5-9b",
                        "include_private": False,
                    },
                )
                self.assertEqual(public_chat.status_code, 200)
                self.assertFalse(
                    analyst.await_args.kwargs["private_evidence"] is not None
                )

                denied_private_chat = self.client.post(
                    f"/api/application/projects/{project_id}/chat",
                    headers=self.headers,
                    json={
                        "question": "What exact value was extracted?",
                        "lm_url": "http://localhost:1234",
                        "model": "qwen/qwen3.5-9b",
                        "include_private": True,
                    },
                )
                self.assertEqual(denied_private_chat.status_code, 403)

                private_chat = self.client.post(
                    f"/api/application/projects/{project_id}/chat",
                    headers={
                        **self.headers,
                        "X-AEGIS-Artifact-Token": "picker-secret",
                    },
                    json={
                        "question": "What exact value was extracted?",
                        "lm_url": "http://localhost:1234",
                        "model": "qwen/qwen3.5-9b",
                        "include_private": True,
                    },
                )
                self.assertEqual(private_chat.status_code, 200)
                private_context = analyst.await_args.kwargs["private_evidence"]
                self.assertIn(self.fixture_value, json.dumps(private_context))
                self.assertEqual(analyst.await_args.kwargs["private_evidence_total"], 1)
                self.assertEqual(prepare_model.await_count, 2)
                prepare_model.assert_awaited_with(
                    "http://localhost:1234",
                    "qwen/qwen3.5-9b",
                )

    def test_application_chat_stream_delivers_progress_deltas_and_final_answer(self):
        with patch.dict(os.environ, {"AEGIS_ARTIFACT_IMPORT_TOKEN": "picker-secret"}):
            project_id, _finding_id = self._import_and_analyze_secret("picker-secret")

            observed = {}

            async def analyst(**kwargs):
                observed.update(kwargs)
                kwargs["on_event"]({"type": "progress", "stage": "prompt", "progress": 1})
                kwargs["on_event"]({"type": "delta", "content": "Grounded "})
                kwargs["on_event"]({"type": "delta", "content": "answer"})
                return "Grounded answer"

            with (
                patch("main._prepare_application_llm", new=AsyncMock(return_value=None)),
                patch("main.ask_application_llm", side_effect=analyst),
            ):
                response = self.client.post(
                    f"/api/application/projects/{project_id}/chat",
                    headers=self.headers,
                    json={
                        "question": "What was found?",
                        "lm_url": "http://localhost:1234",
                        "model": "qwen/qwen3.5-9b",
                        "include_private": False,
                        "stream": True,
                        "history": [
                            {"role": "user", "content": "Can it be exploited?"},
                            {"role": "assistant", "content": "Not from this record."},
                        ],
                    },
                )

            self.assertEqual(response.status_code, 200)
            events = [json.loads(line) for line in response.text.splitlines()]
            self.assertEqual(events[0], {"type": "progress", "stage": "model"})
            self.assertEqual(
                "".join(event.get("content", "") for event in events),
                "Grounded answer",
            )
            self.assertEqual(events[-1]["type"], "complete")
            self.assertEqual(events[-1]["answer"], "Grounded answer")
            self.assertEqual(observed["history"][0]["role"], "user")
            self.assertEqual(observed["history"][1]["content"], "Not from this record.")

    def test_application_chat_stream_returns_partial_as_completion_not_error(self):
        with patch.dict(os.environ, {"AEGIS_ARTIFACT_IMPORT_TOKEN": "picker-secret"}):
            project_id, _finding_id = self._import_and_analyze_secret("picker-secret")

            async def analyst(**kwargs):
                kwargs["on_event"]({"type": "delta", "content": "Useful sentence."})
                raise ApplicationLLMPartialAnswer(
                    "Useful sentence.",
                    "The useful partial answer was preserved.",
                )

            with (
                patch("main._prepare_application_llm", new=AsyncMock(return_value=None)),
                patch("main.ask_application_llm", side_effect=analyst),
            ):
                response = self.client.post(
                    f"/api/application/projects/{project_id}/chat",
                    headers=self.headers,
                    json={
                        "question": "What was found?",
                        "lm_url": "http://localhost:1234",
                        "model": "qwen/qwen3.5-9b",
                        "include_private": False,
                        "stream": True,
                    },
                )

            self.assertEqual(response.status_code, 200)
            events = [json.loads(line) for line in response.text.splitlines()]
            self.assertFalse(any(event["type"] == "error" for event in events))
            self.assertEqual(events[-1]["type"], "complete")
            self.assertEqual(events[-1]["answer"], "Useful sentence.")
            self.assertTrue(events[-1]["truncated"])
            self.assertIn("preserved", events[-1]["notice"])

    def test_project_deletion_requires_desktop_token_and_preserves_source(self):
        with patch.dict(os.environ, {"AEGIS_ARTIFACT_IMPORT_TOKEN": "picker-secret"}):
            project_id, _finding_id = self._import_and_analyze_secret("picker-secret")
            endpoint = f"/api/application/projects/{project_id}"

            denied = self.client.delete(endpoint, headers=self.headers)
            self.assertEqual(denied.status_code, 403)
            self.assertEqual(
                self.client.get(endpoint, headers=self.headers).status_code,
                200,
            )

            deleted = self.client.delete(
                endpoint,
                headers={
                    **self.headers,
                    "X-AEGIS-Artifact-Token": "picker-secret",
                },
            )

        self.assertEqual(deleted.status_code, 200)
        self.assertTrue(deleted.json()["deleted"])
        self.assertEqual(
            self.client.get(endpoint, headers=self.headers).status_code,
            404,
        )
        self.assertTrue(self.secret_source.exists())


if __name__ == "__main__":
    unittest.main()
