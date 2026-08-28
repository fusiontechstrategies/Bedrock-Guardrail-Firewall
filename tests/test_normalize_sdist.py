import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts import normalize_sdist as normalizer


class NormalizeSdistTests(unittest.TestCase):
    def make_archive(self, path: Path, mtime: int) -> None:
        with tarfile.open(path, mode="w:gz") as archive:
            directory = tarfile.TarInfo("package-1.0")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o777
            directory.mtime = mtime
            archive.addfile(directory)
            value = b"synthetic source\n"
            member = tarfile.TarInfo("package-1.0/source.py")
            member.mode = 0o666
            member.mtime = mtime
            member.size = len(value)
            archive.addfile(member, io.BytesIO(value))

    def test_different_archive_times_normalize_to_identical_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.tar.gz"
            second = root / "second.tar.gz"
            self.make_archive(first, 100)
            self.make_archive(second, 200)
            first_hash = normalizer.normalize_sdist(first, 50)
            second_hash = normalizer.normalize_sdist(second, 50)
            self.assertEqual(first_hash, second_hash)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            normalized = first.read_bytes()
            self.assertEqual(first_hash, normalizer.normalize_sdist(first, 50))
            self.assertEqual(normalized, first.read_bytes())
            with tarfile.open(first, mode="r:gz") as archive:
                members = archive.getmembers()
            self.assertEqual([member.mtime for member in members], [50, 50])
            self.assertEqual([member.mode for member in members], [0o755, 0o644])

    def test_link_member_is_rejected_without_changing_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "linked.tar.gz"
            with tarfile.open(path, mode="w:gz") as archive:
                member = tarfile.TarInfo("package-1.0/link")
                member.type = tarfile.SYMTYPE
                member.linkname = "outside"
                archive.addfile(member)
            original = path.read_bytes()
            with self.assertRaisesRegex(
                normalizer.SdistNormalizationError, "link or device"
            ):
                normalizer.normalize_sdist(path, 50)
            self.assertEqual(path.read_bytes(), original)

    def test_duplicate_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.tar.gz"
            source = Path(directory) / "source.txt"
            source.write_text("synthetic", encoding="utf-8")
            with tarfile.open(path, mode="w:gz") as archive:
                archive.add(source, arcname="package-1.0/source.txt")
                archive.add(source, arcname="package-1.0/source.txt")
            with self.assertRaisesRegex(
                normalizer.SdistNormalizationError, "duplicate"
            ):
                normalizer.normalize_sdist(path, 50)

    def test_case_colliding_members_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "collision.tar.gz"
            with tarfile.open(path, mode="w:gz") as archive:
                for name in ("package-1.0/source.py", "package-1.0/SOURCE.py"):
                    value = b"synthetic"
                    member = tarfile.TarInfo(name)
                    member.size = len(value)
                    archive.addfile(member, io.BytesIO(value))
            with self.assertRaisesRegex(
                normalizer.SdistNormalizationError, "non-portable duplicate"
            ):
                normalizer.normalize_sdist(path, 50)

    def test_windows_drive_member_is_rejected_without_changing_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "drive.tar.gz"
            with tarfile.open(path, mode="w:gz") as archive:
                value = b"synthetic"
                member = tarfile.TarInfo("C:/private.txt")
                member.size = len(value)
                archive.addfile(member, io.BytesIO(value))
            original = path.read_bytes()
            with self.assertRaisesRegex(
                normalizer.SdistNormalizationError, "drive path"
            ):
                normalizer.normalize_sdist(path, 50)
            self.assertEqual(original, path.read_bytes())

    def test_epoch_outside_gzip_range_is_rejected_without_changing_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "epoch.tar.gz"
            self.make_archive(path, 100)
            original = path.read_bytes()
            for epoch, message in ((-1, "negative"), (0x100000000, "gzip")):
                with self.subTest(epoch=epoch):
                    with self.assertRaisesRegex(
                        normalizer.SdistNormalizationError, message
                    ):
                        normalizer.normalize_sdist(path, epoch)
                    self.assertEqual(original, path.read_bytes())


if __name__ == "__main__":
    unittest.main()
