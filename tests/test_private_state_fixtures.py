from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import orchestrator as app
from tests.private_state_fixture import PrivateTemporaryDirectory
from tests.test_orchestrator import TEST_KEY, base_config


class PrivateStateFixtureTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows actual short-path control")
    def test_actual_short_path_preserves_lexical_namespace_through_startup(self):
        import ctypes
        import ctypes.wintypes as wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetShortPathNameW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            wintypes.DWORD,
        ]
        kernel.GetShortPathNameW.restype = wintypes.DWORD
        with PrivateTemporaryDirectory() as folder:
            path = Path(folder)
            text = ctypes.create_unicode_buffer(32768)
            count = kernel.GetShortPathNameW(str(path), text, len(text))
            if not count or count >= len(text):
                self.skipTest("Short name is unavailable for the owned fixture")
            short = Path(text.value)
            if str(short).casefold() == str(short.resolve()).casefold():
                self.skipTest("Volume did not assign an 8.3 alias to this fixture")
            original = base_config(path)
            with (
                patch.object(app, "RUNNING_AS_PACKAGE", True),
                patch("orchestrator.Path.cwd", return_value=short),
                patch.dict(
                    os.environ,
                    {
                        "GUARDRAIL_AWS_MODE": "disabled",
                        "GUARDRAIL_PRESIDIO_MODE": "disabled",
                    },
                    clear=True,
                ),
            ):
                config = app.RuntimeConfig.from_env(
                    policy_path=str(original.policy_path),
                    profiles_path=str(original.profiles_path),
                    data_dir="state",
                )
                self.assertEqual(
                    config.data_dir, Path(os.path.abspath(short / "state"))
                )
                self.assertNotEqual(config.data_dir, config.data_dir.resolve())
                system = app.BedrockGuardrailSystem(config, privacy_key=TEST_KEY)
                self.assertTrue(system.doctor()["ready"])
                self.assertEqual(system.config.data_dir, config.data_dir)
                self.assertTrue(config.data_dir.samefile(path / "state"))

    def test_fresh_private_leaf_passes_real_owner_guard_and_public_startup(self):
        for injected in (True, False):
            with self.subTest(injected=injected), PrivateTemporaryDirectory() as folder:
                path = Path(folder)
                descriptor = app._open_private_key(path, create=False, directory=True)
                os.close(descriptor)
                system = app.BedrockGuardrailSystem(
                    base_config(path), privacy_key=TEST_KEY if injected else None
                )
                self.assertTrue(system.doctor()["ready"])

    def test_cleanup_removes_owned_parent_and_private_leaf(self):
        fixture = PrivateTemporaryDirectory()
        parent = Path(fixture._parent.name)
        leaf = Path(fixture.name)
        self.assertTrue(parent.is_dir())
        self.assertTrue(leaf.is_dir())
        fixture.cleanup()
        self.assertFalse(parent.exists())
        self.assertFalse(leaf.exists())

    @unittest.skipUnless(os.name == "nt", "Windows token default-owner control")
    def test_default_administrators_owner_refuses_without_repair(self):
        import ctypes
        import ctypes.wintypes as wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        advapi.GetSecurityInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        advapi.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.LPWSTR),
        ]
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            with app._windows_namespace_handles(path) as parent:
                handle = app._windows_relative_open(path.name, parent, directory=True)
                try:
                    owner, loaded = ctypes.c_void_p(), ctypes.c_void_p()
                    error = advapi.GetSecurityInfo(
                        handle,
                        1,
                        1,
                        ctypes.byref(owner),
                        None,
                        None,
                        None,
                        ctypes.byref(loaded),
                    )
                    if error:
                        raise ctypes.WinError(error)
                    try:
                        text = wintypes.LPWSTR()
                        if not advapi.ConvertSidToStringSidW(owner, ctypes.byref(text)):
                            raise ctypes.WinError(ctypes.get_last_error())
                        try:
                            owner_value = text.value
                        finally:
                            kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
                    finally:
                        kernel.LocalFree(loaded)
                finally:
                    kernel.CloseHandle(handle)
            if owner_value != "S-1-5-32-544":
                self.skipTest("Token did not create an Administrators-owned fixture")
            with self.assertRaises(app.ConfigurationError):
                app.BedrockGuardrailSystem(base_config(path), privacy_key=TEST_KEY)
            self.assertEqual(list(path.iterdir()), [])
