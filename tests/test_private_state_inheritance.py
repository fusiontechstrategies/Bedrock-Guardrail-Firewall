from __future__ import annotations

import os
import stat
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import orchestrator as app
from tests.private_state_fixture import PrivateTemporaryDirectory
from tests.test_orchestrator import base_config


class PrivateStateInheritanceTests(unittest.TestCase):
    def test_private_acl_metadata_requires_exact_protected_owner_grant(self):
        for directory in (False, True):
            owner = (0, 3 if directory else 0, 0x001F01FF, True)
            app._validate_private_windows_acl(0x1000, [owner], directory=directory)
            for aces, control in (
                ([owner, (0, 0, 0x120089, False)], 0x1000),
                ([owner, (0, 11, 0x120089, False)], 0x1000),
                ([owner, (0, 9, 0x120089, False)], 0x1000),
                ([(0, owner[1], owner[2], False)], 0x1000),
                ([(5, owner[1], owner[2], True)], 0x1000),
                ([owner], 0),
                ([], 0x1000),
            ):
                with (
                    self.subTest(directory=directory, aces=aces, control=control),
                    self.assertRaises(app.ConfigurationError),
                ):
                    app._validate_private_windows_acl(
                        control, aces, directory=directory
                    )

    def test_atomic_creation_and_replacement_use_private_descriptors(self):
        with PrivateTemporaryDirectory(prefix="private-state-positive-") as directory:
            path = Path(directory) / "state.json"
            original = app._open_private_key
            calls = []

            def record(path, **kwargs):
                calls.append(
                    (Path(path).name, kwargs.get("create"), kwargs.get("parent_fd"))
                )
                return original(path, **kwargs)

            with patch.object(app, "_open_private_key", side_effect=record):
                app._atomic_json_write(path, {"events": 1}, create_only=True)
                app._atomic_json_write(path, {"events": 2})
            self.assertEqual(
                app._load_json_file(path, private_state=True), {"events": 2}
            )
            self.assertEqual(
                len([item for item in calls if item[0].endswith(".tmp") and item[1]]), 2
            )
            self.assertTrue(
                all(item[2] is not None for item in calls if item[0].endswith(".tmp"))
            )
            with self.assertRaises(app.StorageError):
                app._atomic_json_write(path, {"events": 3}, create_only=True)
            self.assertEqual(
                app._load_json_file(path, private_state=True), {"events": 2}
            )
            self.assertEqual(list(Path(directory).glob("*.tmp")), [])

    def test_existing_private_admission_failure_precedes_temp_creation(self):
        with PrivateTemporaryDirectory(prefix="private-state-admission-") as directory:
            path = Path(directory) / "state.json"
            app._atomic_json_write(path, {"events": 1})
            original = app._open_private_key
            created = []

            def refuse_leaf(candidate, **kwargs):
                if Path(candidate).name == path.name and not kwargs["create"]:
                    raise app.ConfigurationError("mocked non-private leaf metadata")
                if Path(candidate).name.endswith(".tmp"):
                    created.append(candidate)
                return original(candidate, **kwargs)

            with patch.object(app, "_open_private_key", side_effect=refuse_leaf):
                with self.assertRaises(app.StorageError):
                    app._atomic_json_write(path, {"events": 2})
                with self.assertRaises(app.ConfigurationError):
                    app._load_json_file(path, private_state=True)
            self.assertEqual(created, [])
            self.assertEqual(
                app._load_json_file(path, private_state=True), {"events": 1}
            )

    def test_new_evidence_directories_and_reservation_are_private(self):
        with PrivateTemporaryDirectory(
            prefix="private-evidence-positive-"
        ) as directory:
            root = Path(directory)
            store = app.IncidentStore(root)
            result = Path(store.create({"action": "block", "subject_id": "synthetic"}))
            self.assertEqual(
                app._load_json_file(result, private_state=True)["action"], "block"
            )
            for name in ("incidents", ".evidence-reservations", "locks"):
                with app._auxiliary_namespace(root / name):
                    pass
            self.assertEqual(list((root / ".evidence-reservations").iterdir()), [])

    def test_existing_evidence_namespace_refusal_precedes_any_record(self):
        with PrivateTemporaryDirectory(
            prefix="private-evidence-admission-"
        ) as directory:
            root = Path(directory)
            config = base_config(root)
            original = app._open_private_key
            for name in ("reviews", "incidents", ".evidence-reservations"):
                with app._auxiliary_namespace(root / name):
                    pass

                def refuse(candidate, *, name=name, **kwargs):
                    if Path(candidate) == root / name and not kwargs["create"]:
                        raise app.ConfigurationError(
                            "mocked confidentiality ACL refusal"
                        )
                    return original(candidate, **kwargs)

                provider = app.AwsClientProvider(config, live_authorized=False)
                with (
                    self.subTest(name=name),
                    patch.object(app, "_open_private_key", side_effect=refuse),
                    self.assertRaises(app.ConfigurationError),
                ):
                    if name == "reviews":
                        app.ReviewStore(config, provider).create(
                            {"action": "review"}, "l1"
                        )
                    elif name == "incidents":
                        app.IncidentStore(root).create({"action": "block"})
                    else:
                        with app._evidence_budget(root, 10):
                            self.fail(
                                "Refused namespace must not enter reservation body"
                            )
                self.assertEqual(list((root / name).iterdir()), [])

    def test_accounting_removed_leaf_is_absent_but_acl_refusal_is_not_absence(self):
        with PrivateTemporaryDirectory(prefix="private-accounting-") as directory:
            root = Path(directory)
            with app._auxiliary_namespace(root / "reviews"):
                pass
            leaf = root / "reviews" / "ordinary.json"
            app._atomic_json_write(leaf, {"action": "review"})
            original = app._open_private_key
            observed = []

            def metadata(candidate, **kwargs):
                if Path(candidate) == leaf and kwargs.get("share_delete"):
                    observed.append(kwargs)
                    raise FileNotFoundError("mocked removed enumerated leaf")
                return original(candidate, **kwargs)

            with (
                patch.object(app, "_open_private_key", side_effect=metadata),
                app._evidence_budget(root, 10),
            ):
                pass
            self.assertTrue(observed)

            def refuse(candidate, **kwargs):
                if Path(candidate) == leaf and kwargs.get("share_delete"):
                    raise app.ConfigurationError("mocked unsafe existing ACL")
                return original(candidate, **kwargs)

            with (
                patch.object(app, "_open_private_key", side_effect=refuse),
                self.assertRaises(app.ConfigurationError),
                app._evidence_budget(root, 10),
            ):
                self.fail("An ACL refusal cannot be treated as an absent file")

    def test_one_accounting_snapshot_retains_single_link_admission(self):
        with PrivateTemporaryDirectory(prefix="private-snapshot-") as directory:
            root = Path(directory)
            with app._auxiliary_namespace(root / "reviews"):
                pass
            leaf = root / "reviews" / "ordinary.json"
            app._atomic_json_write(leaf, {"action": "review"})
            original_open = app._open_private_key
            original_stat = os.fstat
            original_close = os.close
            selected = {}
            reads = []

            def opened(candidate, **kwargs):
                descriptor = original_open(candidate, **kwargs)
                if Path(candidate) == leaf and kwargs.get("share_delete"):
                    selected[descriptor] = 0
                return descriptor

            def snapshot(descriptor):
                info = original_stat(descriptor)
                if descriptor in selected:
                    selected[descriptor] += 1
                    reads.append(selected[descriptor])
                    if selected[descriptor] > 1:
                        return types.SimpleNamespace(st_nlink=0)
                return info

            def closed(descriptor):
                selected.pop(descriptor, None)
                return original_close(descriptor)

            with (
                patch.object(app, "_open_private_key", side_effect=opened),
                patch.object(os, "fstat", side_effect=snapshot),
                patch.object(os, "close", side_effect=closed),
                app._evidence_budget(root, 10),
            ):
                pass
            self.assertEqual(reads, [1])
            info = os.stat(leaf)
            values = {name: getattr(info, name) for name in ("st_mode", "st_uid")}
            for links in (0, 2, 3):
                with self.subTest(links=links), self.assertRaises(app.StorageError):
                    app._validate_auxiliary_info(
                        types.SimpleNamespace(**values, st_nlink=links)
                    )
            with self.assertRaises(app.StorageError):
                app._validate_auxiliary_info(
                    types.SimpleNamespace(
                        st_mode=stat.S_IFDIR, st_nlink=1, st_uid=info.st_uid
                    )
                )

    def test_review_and_incident_publication_coordinate_with_quota_lock(self):
        with PrivateTemporaryDirectory(prefix="private-publication-lock-") as directory:
            root = Path(directory)
            config = base_config(root)
            expected = root / "locks" / "evidence-budget.lock"
            active = []
            observations = []
            original_lock = app.CrossProcessFileLock
            original_dump = app.json.dump

            class RecordedLock(original_lock):
                def __enter__(self):
                    result = super().__enter__()
                    active.append(self.path)
                    return result

                def __exit__(self, *args):
                    active.remove(self.path)
                    return super().__exit__(*args)

            def dump(value, handle, **kwargs):
                if value.get("action") in {"review", "block"}:
                    observations.append(expected in active)
                return original_dump(value, handle, **kwargs)

            with (
                patch.object(app, "CrossProcessFileLock", RecordedLock),
                patch.object(app.json, "dump", side_effect=dump),
            ):
                app.IncidentStore(root).create({"action": "block"})
                provider = app.AwsClientProvider(config, live_authorized=False)
                app.ReviewStore(config, provider).create({"action": "review"}, "l1")
            self.assertEqual(observations, [True, True])
            self.assertEqual(active, [])

    @unittest.skipUnless(os.name == "nt", "Windows final namespace metadata control")
    def test_windows_final_namespace_does_not_use_traversal_admission(self):
        with PrivateTemporaryDirectory(prefix="private-root-positive-") as directory:
            original = app._open_private_key
            final = []

            def record(candidate, **kwargs):
                if Path(candidate) == Path(directory) and not kwargs["create"]:
                    final.append(kwargs.get("trusted_parent"))
                return original(candidate, **kwargs)

            with (
                patch.object(app, "_open_private_key", side_effect=record),
                app._auxiliary_namespace(Path(directory), trusted_parent=True),
            ):
                pass
            self.assertEqual(final, [False])
