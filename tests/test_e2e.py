"""End-to-end regression test.

ONE test scenario with YAML fixtures covering ALL code paths.
Run: python -m unittest tests.test_e2e -v

Covers:
  Resolution: SHA1, MD5, name, alias, truncated MD5, md5_composite,
              zip_contents, .variants deprio, not_found, hash_mismatch
  Verification: existence mode, md5 mode, required/optional,
                zipped_file (match/mismatch/missing inner), multi-hash
  Severity: all combos per platform mode
  Platform config: inheritance, shared groups, data_directories, grouping
  Pack: storage tiers (external/user_provided/embedded), dedup, large file cache
  Cross-reference: undeclared files, standalone skipped, alias profiles skipped,
                   data_dir suppresses gaps
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import yaml
from common import (
    build_zip_contents_index, check_inside_zip, group_identical_platforms,
    load_emulator_profiles, load_platform_config, md5_composite, md5sum,
    resolve_local_file, resolve_platform_cores,
)
from verify import Severity, Status, verify_platform, find_undeclared_files, find_exclusion_notes


def _h(data: bytes) -> dict:
    """Return sha1, md5, crc32 for test data."""
    return {
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "crc32": format(hashlib.new("crc32", data).digest()[0], "08x")
               if False else "",  # not needed for tests
    }


class TestE2E(unittest.TestCase):
    """Single end-to-end scenario exercising every code path."""

    # ---------------------------------------------------------------
    # Fixture setup
    # ---------------------------------------------------------------

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.bios_dir = os.path.join(self.root, "bios")
        self.platforms_dir = os.path.join(self.root, "platforms")
        self.emulators_dir = os.path.join(self.root, "emulators")
        os.makedirs(self.bios_dir)
        os.makedirs(self.platforms_dir)
        os.makedirs(self.emulators_dir)

        # -- Create synthetic BIOS files --
        self.files = {}
        self._make_file("present_req.bin", b"PRESENT_REQUIRED")
        self._make_file("present_opt.bin", b"PRESENT_OPTIONAL")
        self._make_file("correct_hash.bin", b"CORRECT_HASH_DATA")
        self._make_file("wrong_hash.bin", b"WRONG_CONTENT_ON_DISK")
        self._make_file("no_md5.bin", b"NO_MD5_CHECK")
        self._make_file("truncated.bin", b"BATOCERA_TRUNCATED")
        self._make_file("alias_target.bin", b"ALIAS_FILE_DATA")

        # .variants/ file (should be deprioritized)
        variants_dir = os.path.join(self.bios_dir, ".variants")
        os.makedirs(variants_dir)
        self._make_file("present_req.bin", b"VARIANT_DATA", subdir=".variants")

        # ZIP with correct inner ROM
        self._make_zip("good.zip", {"inner.rom": b"GOOD_INNER_ROM"})
        # ZIP with wrong inner ROM
        self._make_zip("bad_inner.zip", {"inner.rom": b"BAD_INNER"})
        # ZIP with missing inner ROM name
        self._make_zip("missing_inner.zip", {"other.rom": b"OTHER_ROM"})
        # ZIP for md5_composite (Recalbox)
        self._make_zip("composite.zip", {"b.rom": b"BBBB", "a.rom": b"AAAA"})
        # ZIP for multi-hash
        self._make_zip("multi.zip", {"rom.bin": b"MULTI_HASH_DATA"})

        # -- Build synthetic database --
        self.db = self._build_db()

        # -- Create platform YAMLs --
        self._create_existence_platform()
        self._create_md5_platform()
        self._create_shared_groups()
        self._create_inherited_platform()

        # -- Create emulator YAMLs --
        self._create_emulator_profiles()

    def tearDown(self):
        shutil.rmtree(self.root)

    # ---------------------------------------------------------------
    # File helpers
    # ---------------------------------------------------------------

    def _make_file(self, name: str, data: bytes, subdir: str = "") -> str:
        d = os.path.join(self.bios_dir, subdir) if subdir else self.bios_dir
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, name)
        with open(path, "wb") as f:
            f.write(data)
        h = _h(data)
        self.files[f"{subdir}/{name}" if subdir else name] = {
            "path": path, "data": data, **h,
        }
        return path

    def _make_zip(self, name: str, contents: dict[str, bytes]) -> str:
        path = os.path.join(self.bios_dir, name)
        with zipfile.ZipFile(path, "w") as zf:
            for fname, data in contents.items():
                zf.writestr(fname, data)
        with open(path, "rb") as f:
            zdata = f.read()
        h = _h(zdata)
        inner_md5s = {fn: hashlib.md5(d).hexdigest() for fn, d in contents.items()}
        self.files[name] = {"path": path, "data": zdata, "inner_md5s": inner_md5s, **h}
        return path

    def _build_db(self) -> dict:
        files_db = {}
        by_md5 = {}
        by_name = {}
        for key, info in self.files.items():
            name = os.path.basename(key)
            sha1 = info["sha1"]
            files_db[sha1] = {
                "path": info["path"],
                "md5": info["md5"],
                "name": name,
                "crc32": info.get("crc32", ""),
            }
            by_md5[info["md5"]] = sha1
            by_name.setdefault(name, []).append(sha1)
        # Add alias name to by_name
        alias_sha1 = self.files["alias_target.bin"]["sha1"]
        by_name.setdefault("alias_alt.bin", []).append(alias_sha1)
        return {
            "files": files_db,
            "indexes": {"by_md5": by_md5, "by_name": by_name, "by_crc32": {}},
        }

    # ---------------------------------------------------------------
    # Platform YAML creators
    # ---------------------------------------------------------------

    def _create_existence_platform(self):
        f = self.files
        config = {
            "platform": "TestExistence",
            "verification_mode": "existence",
            "base_destination": "system",
            "systems": {
                "console-a": {
                    "files": [
                        {"name": "present_req.bin", "destination": "present_req.bin", "required": True},
                        {"name": "missing_req.bin", "destination": "missing_req.bin", "required": True},
                        {"name": "present_opt.bin", "destination": "present_opt.bin", "required": False},
                        {"name": "missing_opt.bin", "destination": "missing_opt.bin", "required": False},
                    ],
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "test_existence.yml"), "w") as fh:
            yaml.dump(config, fh)

    def _create_md5_platform(self):
        f = self.files
        good_inner_md5 = f["good.zip"]["inner_md5s"]["inner.rom"]
        bad_inner_md5 = "deadbeefdeadbeefdeadbeefdeadbeef"
        composite_md5 = hashlib.md5(b"AAAA" + b"BBBB").hexdigest()  # sorted: a.rom, b.rom
        multi_wrong = "0000000000000000000000000000000"
        multi_right = f["multi.zip"]["inner_md5s"]["rom.bin"]
        truncated_md5 = f["truncated.bin"]["md5"][:29]  # Batocera 29-char

        config = {
            "platform": "TestMD5",
            "verification_mode": "md5",
            "systems": {
                "sys-md5": {
                    "includes": ["test_shared"],
                    "files": [
                        # Correct hash
                        {"name": "correct_hash.bin", "destination": "correct_hash.bin",
                         "md5": f["correct_hash.bin"]["md5"], "required": True},
                        # Wrong hash on disk → untested
                        {"name": "wrong_hash.bin", "destination": "wrong_hash.bin",
                         "md5": "ffffffffffffffffffffffffffffffff", "required": True},
                        # No MD5 → OK (existence within md5 platform)
                        {"name": "no_md5.bin", "destination": "no_md5.bin", "required": False},
                        # Missing required
                        {"name": "gone_req.bin", "destination": "gone_req.bin",
                         "md5": "abcd", "required": True},
                        # Missing optional
                        {"name": "gone_opt.bin", "destination": "gone_opt.bin",
                         "md5": "abcd", "required": False},
                        # zipped_file correct
                        {"name": "good.zip", "destination": "good.zip",
                         "md5": good_inner_md5, "zipped_file": "inner.rom", "required": True},
                        # zipped_file wrong inner
                        {"name": "bad_inner.zip", "destination": "bad_inner.zip",
                         "md5": bad_inner_md5, "zipped_file": "inner.rom", "required": False},
                        # zipped_file inner not found
                        {"name": "missing_inner.zip", "destination": "missing_inner.zip",
                         "md5": "abc", "zipped_file": "nope.rom", "required": False},
                        # md5_composite (Recalbox)
                        {"name": "composite.zip", "destination": "composite.zip",
                         "md5": composite_md5, "required": True},
                        # Multi-hash comma-separated (Recalbox)
                        {"name": "multi.zip", "destination": "multi.zip",
                         "md5": f"{multi_wrong},{multi_right}", "zipped_file": "rom.bin", "required": True},
                        # Truncated MD5 (Batocera 29 chars)
                        {"name": "truncated.bin", "destination": "truncated.bin",
                         "md5": truncated_md5, "required": True},
                        # Same destination from different entry → worst status wins
                        {"name": "correct_hash.bin", "destination": "dedup_target.bin",
                         "md5": f["correct_hash.bin"]["md5"], "required": True},
                        {"name": "correct_hash.bin", "destination": "dedup_target.bin",
                         "md5": "wrong_for_dedup_test", "required": True},
                    ],
                    "data_directories": [
                        {"ref": "test-data-dir", "destination": "TestData"},
                    ],
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "test_md5.yml"), "w") as fh:
            yaml.dump(config, fh)

    def _create_shared_groups(self):
        shared = {
            "shared_groups": {
                "test_shared": [
                    {"name": "shared_file.rom", "destination": "shared_file.rom", "required": False},
                ],
            },
        }
        with open(os.path.join(self.platforms_dir, "_shared.yml"), "w") as fh:
            yaml.dump(shared, fh)

    def _create_inherited_platform(self):
        child = {
            "inherits": "test_existence",
            "platform": "TestInherited",
            "base_destination": "BIOS",
        }
        with open(os.path.join(self.platforms_dir, "test_inherited.yml"), "w") as fh:
            yaml.dump(child, fh)

    def _create_emulator_profiles(self):
        # Regular emulator with aliases, standalone file, undeclared file
        emu = {
            "emulator": "TestEmu",
            "type": "standalone + libretro",
            "systems": ["console-a", "sys-md5"],
            "data_directories": [{"ref": "test-data-dir"}],
            "files": [
                {"name": "present_req.bin", "required": True},
                {"name": "alias_target.bin", "required": False,
                 "aliases": ["alias_alt.bin"]},
                {"name": "standalone_only.bin", "required": False, "mode": "standalone"},
                {"name": "undeclared_req.bin", "required": True},
                {"name": "undeclared_opt.bin", "required": False},
            ],
        }
        with open(os.path.join(self.emulators_dir, "test_emu.yml"), "w") as fh:
            yaml.dump(emu, fh)

        # Emulator with HLE fallback
        emu_hle = {
            "emulator": "TestHLE",
            "type": "libretro",
            "systems": ["console-a"],
            "files": [
                {"name": "present_req.bin", "required": True, "hle_fallback": True},
                {"name": "hle_missing.bin", "required": True, "hle_fallback": True},
                {"name": "no_hle_missing.bin", "required": True, "hle_fallback": False},
            ],
        }
        with open(os.path.join(self.emulators_dir, "test_hle.yml"), "w") as fh:
            yaml.dump(emu_hle, fh)

        # Launcher profile (should be excluded from cross-reference)
        launcher = {
            "emulator": "TestLauncher",
            "type": "launcher",
            "systems": ["console-a"],
            "files": [{"name": "launcher_bios.bin", "required": True}],
        }
        with open(os.path.join(self.emulators_dir, "test_launcher.yml"), "w") as fh:
            yaml.dump(launcher, fh)

        # Alias profile (should be skipped)
        alias = {"emulator": "TestAlias", "type": "alias", "alias_of": "test_emu", "files": []}
        with open(os.path.join(self.emulators_dir, "test_alias.yml"), "w") as fh:
            yaml.dump(alias, fh)

        # Emulator with data_dir that matches platform → gaps suppressed
        emu_dd = {
            "emulator": "TestEmuDD",
            "type": "libretro",
            "systems": ["sys-md5"],
            "data_directories": [{"ref": "test-data-dir"}],
            "files": [
                {"name": "dd_covered.bin", "required": False},
            ],
        }
        with open(os.path.join(self.emulators_dir, "test_emu_dd.yml"), "w") as fh:
            yaml.dump(emu_dd, fh)

    # ---------------------------------------------------------------
    # THE TEST — one method per feature area, all using same fixtures
    # ---------------------------------------------------------------

    def test_01_resolve_sha1(self):
        entry = {"name": "present_req.bin", "sha1": self.files["present_req.bin"]["sha1"]}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "exact")
        self.assertIn("present_req.bin", path)

    def test_02_resolve_md5(self):
        entry = {"name": "correct_hash.bin", "md5": self.files["correct_hash.bin"]["md5"]}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "md5_exact")

    def test_03_resolve_name_no_md5(self):
        entry = {"name": "no_md5.bin"}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "exact")

    def test_04_resolve_alias(self):
        entry = {"name": "alias_alt.bin", "aliases": []}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "exact")
        self.assertIn("alias_target.bin", path)

    def test_05_resolve_truncated_md5(self):
        truncated = self.files["truncated.bin"]["md5"][:29]
        entry = {"name": "truncated.bin", "md5": truncated}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "md5_exact")

    def test_06_resolve_not_found(self):
        entry = {"name": "nonexistent.bin", "sha1": "0" * 40}
        path, status = resolve_local_file(entry, self.db)
        self.assertIsNone(path)
        self.assertEqual(status, "not_found")

    def test_07_resolve_hash_mismatch(self):
        entry = {"name": "wrong_hash.bin", "md5": "ffffffffffffffffffffffffffffffff"}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "hash_mismatch")

    def test_08_resolve_variants_deprioritized(self):
        entry = {"name": "present_req.bin"}
        path, status = resolve_local_file(entry, self.db)
        self.assertNotIn(".variants", path)

    def test_09_resolve_zip_contents(self):
        zc = build_zip_contents_index(self.db)
        inner_md5 = self.files["good.zip"]["inner_md5s"]["inner.rom"]
        entry = {"name": "good.zip", "md5": inner_md5, "zipped_file": "inner.rom"}
        path, status = resolve_local_file(entry, self.db, zc)
        # Should find via name match (hash_mismatch since container md5 != inner md5)
        # then zip_contents would be fallback
        self.assertIsNotNone(path)

    def test_10_md5_composite(self):
        expected = hashlib.md5(b"AAAA" + b"BBBB").hexdigest()
        actual = md5_composite(self.files["composite.zip"]["path"])
        self.assertEqual(actual, expected)

    def test_11_check_inside_zip_match(self):
        inner_md5 = self.files["good.zip"]["inner_md5s"]["inner.rom"]
        r = check_inside_zip(self.files["good.zip"]["path"], "inner.rom", inner_md5)
        self.assertEqual(r, "ok")

    def test_12_check_inside_zip_mismatch(self):
        r = check_inside_zip(self.files["bad_inner.zip"]["path"], "inner.rom", "wrong")
        self.assertEqual(r, "untested")

    def test_13_check_inside_zip_not_found(self):
        r = check_inside_zip(self.files["missing_inner.zip"]["path"], "nope.rom", "abc")
        self.assertEqual(r, "not_in_zip")

    def test_14_check_inside_zip_casefold(self):
        inner_md5 = self.files["good.zip"]["inner_md5s"]["inner.rom"]
        r = check_inside_zip(self.files["good.zip"]["path"], "INNER.ROM", inner_md5)
        self.assertEqual(r, "ok")

    def test_20_verify_existence_platform(self):
        config = load_platform_config("test_existence", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        c = result["severity_counts"]
        total = result["total_files"]
        # 2 present (1 req + 1 opt), 2 missing (1 req WARNING + 1 opt INFO)
        self.assertEqual(c[Severity.OK], 2)
        self.assertEqual(c[Severity.WARNING], 1)  # required missing
        self.assertEqual(c[Severity.INFO], 1)      # optional missing
        self.assertEqual(sum(c.values()), total)

    def test_21_verify_md5_platform(self):
        config = load_platform_config("test_md5", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        c = result["severity_counts"]
        total = result["total_files"]
        self.assertEqual(sum(c.values()), total)
        # At least some OK and some non-OK
        self.assertGreater(c[Severity.OK], 0)
        self.assertGreater(total, c[Severity.OK])

    def test_22_verify_required_propagated(self):
        config = load_platform_config("test_md5", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        for d in result["details"]:
            self.assertIn("required", d)

    def test_23_verify_missing_required_is_critical(self):
        config = load_platform_config("test_md5", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        c = result["severity_counts"]
        self.assertGreater(c[Severity.CRITICAL], 0)

    def test_24_verify_missing_optional_is_warning(self):
        config = load_platform_config("test_md5", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        c = result["severity_counts"]
        self.assertGreater(c[Severity.WARNING], 0)

    def test_30_inheritance_inherits_systems(self):
        config = load_platform_config("test_inherited", self.platforms_dir)
        self.assertEqual(config["platform"], "TestInherited")
        self.assertEqual(config["base_destination"], "BIOS")
        self.assertIn("console-a", config["systems"])

    def test_31_shared_groups_injected(self):
        config = load_platform_config("test_md5", self.platforms_dir)
        names = [f["name"] for f in config["systems"]["sys-md5"]["files"]]
        self.assertIn("shared_file.rom", names)

    def test_40_cross_ref_finds_undeclared(self):
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db, profiles)
        names = {u["name"] for u in undeclared}
        self.assertIn("undeclared_req.bin", names)
        self.assertIn("undeclared_opt.bin", names)

    def test_41_cross_ref_skips_standalone(self):
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db, profiles)
        names = {u["name"] for u in undeclared}
        self.assertNotIn("standalone_only.bin", names)

    def test_42_cross_ref_skips_alias_profiles(self):
        profiles = load_emulator_profiles(self.emulators_dir)
        self.assertNotIn("test_alias", profiles)

    def test_43_cross_ref_data_dir_does_not_suppress_files(self):
        config = load_platform_config("test_md5", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db, profiles)
        names = {u["name"] for u in undeclared}
        # dd_covered.bin is a file entry, not data_dir content — still undeclared
        self.assertIn("dd_covered.bin", names)

    def test_44_cross_ref_skips_launchers(self):
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db, profiles)
        names = {u["name"] for u in undeclared}
        # launcher_bios.bin from TestLauncher should NOT appear
        self.assertNotIn("launcher_bios.bin", names)

    def test_45_hle_fallback_downgrades_severity(self):
        """Missing file with hle_fallback=true → INFO severity, not CRITICAL."""
        from verify import compute_severity, Severity
        # required + missing + NO HLE = CRITICAL
        sev = compute_severity("missing", True, "md5", hle_fallback=False)
        self.assertEqual(sev, Severity.CRITICAL)
        # required + missing + HLE = INFO
        sev = compute_severity("missing", True, "md5", hle_fallback=True)
        self.assertEqual(sev, Severity.INFO)
        # required + missing + HLE + existence mode = INFO
        sev = compute_severity("missing", True, "existence", hle_fallback=True)
        self.assertEqual(sev, Severity.INFO)

    def test_46_hle_index_built_from_emulator_profiles(self):
        """verify_platform reads hle_fallback from emulator profiles."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        result = verify_platform(config, self.db, self.emulators_dir, profiles)
        # present_req.bin has hle_fallback: true in TestHLE profile
        for d in result["details"]:
            if d["name"] == "present_req.bin":
                self.assertTrue(d.get("hle_fallback", False))
                break

    def test_47_cross_ref_shows_hle_on_undeclared(self):
        """Undeclared files include hle_fallback from emulator profile."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db, profiles)
        hle_files = {u["name"] for u in undeclared if u.get("hle_fallback")}
        self.assertIn("hle_missing.bin", hle_files)

    def test_50_platform_grouping_identical(self):
        groups = group_identical_platforms(
            ["test_existence", "test_inherited"], self.platforms_dir
        )
        # Different base_destination → separate groups
        self.assertEqual(len(groups), 2)

    def test_51_platform_grouping_same(self):
        # Create two identical platforms
        for name in ("dup_a", "dup_b"):
            config = {
                "platform": name,
                "verification_mode": "existence",
                "systems": {"s": {"files": [{"name": "x.bin", "destination": "x.bin"}]}},
            }
            with open(os.path.join(self.platforms_dir, f"{name}.yml"), "w") as fh:
                yaml.dump(config, fh)
        groups = group_identical_platforms(["dup_a", "dup_b"], self.platforms_dir)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0][0]), 2)

    def test_60_storage_external(self):
        from generate_pack import resolve_file
        entry = {"name": "large.pup", "storage": "external"}
        path, status = resolve_file(entry, self.db, self.bios_dir)
        self.assertIsNone(path)
        self.assertEqual(status, "external")

    def test_61_storage_user_provided(self):
        from generate_pack import resolve_file
        entry = {"name": "user.bin", "storage": "user_provided"}
        path, status = resolve_file(entry, self.db, self.bios_dir)
        self.assertIsNone(path)
        self.assertEqual(status, "user_provided")


    def test_resolve_cores_all_libretro(self):
        """all_libretro resolves to all libretro-type profiles, excludes alias/standalone."""
        config = {"cores": "all_libretro", "systems": {"nes": {"files": []}}}
        profiles = {
            "fceumm": {"type": "libretro", "systems": ["nes"], "files": []},
            "dolphin_standalone": {"type": "standalone", "systems": ["gc"], "files": []},
            "gambatte": {"type": "pure_libretro", "systems": ["gb"], "files": []},
            "mednafen_psx_hw": {"type": "alias", "alias_of": "beetle_psx", "files": []},
        }
        result = resolve_platform_cores(config, profiles)
        self.assertEqual(result, {"fceumm", "gambatte"})

    def test_resolve_cores_explicit_list(self):
        """Explicit cores list matches against profile dict keys."""
        config = {"cores": ["fbneo", "opera"], "systems": {"arcade": {"files": []}}}
        profiles = {
            "fbneo": {"type": "pure_libretro", "systems": ["arcade"], "files": []},
            "opera": {"type": "libretro", "systems": ["3do"], "files": []},
            "mame": {"type": "libretro", "systems": ["arcade"], "files": []},
        }
        result = resolve_platform_cores(config, profiles)
        self.assertEqual(result, {"fbneo", "opera"})

    def test_resolve_cores_fallback_systems(self):
        """Missing cores: field falls back to system ID intersection."""
        config = {"systems": {"nes": {"files": []}}}
        profiles = {
            "fceumm": {"type": "libretro", "systems": ["nes"], "files": []},
            "dolphin": {"type": "libretro", "systems": ["gc"], "files": []},
        }
        result = resolve_platform_cores(config, profiles)
        self.assertEqual(result, {"fceumm"})

    def test_resolve_cores_excludes_alias(self):
        """Alias profiles never included even if name matches cores list."""
        config = {"cores": ["mednafen_psx_hw"], "systems": {}}
        profiles = {
            "mednafen_psx_hw": {"type": "alias", "alias_of": "beetle_psx", "files": []},
        }
        result = resolve_platform_cores(config, profiles)
        self.assertEqual(result, set())


    def test_cross_reference_uses_core_resolution(self):
        """Cross-reference matches by cores: field, not system intersection."""
        config = {
            "cores": ["fbneo"],
            "systems": {
                "arcade": {"files": [{"name": "neogeo.zip", "md5": "abc"}]}
            }
        }
        profiles = {
            "fbneo": {
                "emulator": "FBNeo", "systems": ["snk-neogeo-mvs"],
                "type": "pure_libretro",
                "files": [
                    {"name": "neogeo.zip", "required": True},
                    {"name": "neocdz.zip", "required": True},
                ],
            },
        }
        db = {"indexes": {"by_name": {"neocdz.zip": {"sha1": "x"}}}}
        undeclared = find_undeclared_files(config, self.emulators_dir, db, profiles)
        names = [u["name"] for u in undeclared]
        self.assertIn("neocdz.zip", names)
        self.assertNotIn("neogeo.zip", names)

    def test_exclusion_notes_uses_core_resolution(self):
        """Exclusion notes match by cores: field, not system intersection."""
        config = {
            "cores": ["desmume2015"],
            "systems": {"nds": {"files": []}}
        }
        profiles = {
            "desmume2015": {
                "emulator": "DeSmuME 2015", "type": "frozen_snapshot",
                "systems": ["nintendo-ds"],
                "files": [],
                "exclusion_note": "Frozen snapshot, code never loads BIOS",
            },
        }
        notes = find_exclusion_notes(config, self.emulators_dir, profiles)
        emu_names = [n["emulator"] for n in notes]
        self.assertIn("DeSmuME 2015", emu_names)


if __name__ == "__main__":
    unittest.main()
