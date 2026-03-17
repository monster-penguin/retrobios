#!/usr/bin/env python3
"""Scraper for RetroBat batocera-systems.json.

Source: https://github.com/RetroBat-Official/emulatorlauncher
Format: JSON with system keys containing biosFiles arrays
Hash: MD5 primary
"""

from __future__ import annotations

import json
import sys
import urllib.request
import urllib.error

try:
    from .base_scraper import BaseScraper, BiosRequirement, fetch_github_latest_version
except ImportError:
    from base_scraper import BaseScraper, BiosRequirement, fetch_github_latest_version

PLATFORM_NAME = "retrobat"

SOURCE_URL = (
    "https://raw.githubusercontent.com/RetroBat-Official/emulatorlauncher/"
    "master/batocera-systems/Resources/batocera-systems.json"
)

GITHUB_REPO = "RetroBat-Official/retrobat"


class Scraper(BaseScraper):
    """Scraper for RetroBat batocera-systems.json."""

    def __init__(self, url: str = SOURCE_URL):
        self.url = url
        self._raw_data: str | None = None
        self._parsed: dict | None = None

    def _fetch_raw(self) -> str:
        if self._raw_data is not None:
            return self._raw_data

        try:
            req = urllib.request.Request(self.url, headers={"User-Agent": "retrobios-scraper/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                self._raw_data = resp.read().decode("utf-8")
                return self._raw_data
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to fetch {self.url}: {e}") from e

    def _parse_json(self) -> dict:
        if self._parsed is not None:
            return self._parsed

        raw = self._fetch_raw()
        try:
            self._parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON: {e}") from e
        return self._parsed

    def fetch_requirements(self) -> list[BiosRequirement]:
        """Parse batocera-systems.json and return BIOS requirements."""
        raw = self._fetch_raw()

        if not self.validate_format(raw):
            raise ValueError("batocera-systems.json format validation failed")

        data = self._parse_json()
        requirements = []

        for sys_key, sys_data in data.items():
            if not isinstance(sys_data, dict):
                continue

            bios_files = sys_data.get("biosFiles", [])
            if not isinstance(bios_files, list):
                continue

            for bios in bios_files:
                if not isinstance(bios, dict):
                    continue

                file_path = bios.get("file", "")
                md5 = bios.get("md5", "")

                if not file_path:
                    continue

                # Strip bios/ prefix from file paths
                if file_path.startswith("bios/"):
                    file_path = file_path[5:]

                name = file_path.split("/")[-1] if "/" in file_path else file_path

                requirements.append(BiosRequirement(
                    name=name,
                    system=sys_key,
                    md5=md5 or None,
                    destination=file_path,
                    required=True,
                ))

        return requirements

    def validate_format(self, raw_data: str) -> bool:
        """Validate that raw_data is valid JSON containing biosFiles entries."""
        try:
            data = json.loads(raw_data)
        except (json.JSONDecodeError, TypeError):
            return False

        if not isinstance(data, dict):
            return False

        has_bios = False
        for sys_key, sys_data in data.items():
            if isinstance(sys_data, dict) and "biosFiles" in sys_data:
                has_bios = True
                break

        return has_bios

    def generate_platform_yaml(self) -> dict:
        """Generate a platform YAML config dict from scraped data."""
        requirements = self.fetch_requirements()

        systems = {}
        for req in requirements:
            if req.system not in systems:
                systems[req.system] = {"files": []}

            entry = {
                "name": req.name,
                "destination": req.destination,
                "required": req.required,
            }
            if req.md5:
                entry["md5"] = req.md5

            systems[req.system]["files"].append(entry)

        version = ""
        tag = fetch_github_latest_version(GITHUB_REPO)
        if tag:
            version = tag

        return {
            "platform": "RetroBat",
            "version": version,
            "homepage": "https://www.retrobat.org",
            "source": SOURCE_URL,
            "base_destination": "bios",
            "hash_type": "md5",
            "verification_mode": "md5",
            "systems": systems,
        }


def main():
    """CLI entry point for testing."""
    import argparse

    parser = argparse.ArgumentParser(description="Scrape RetroBat batocera-systems.json")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", "-o")
    args = parser.parse_args()

    scraper = Scraper()

    try:
        reqs = scraper.fetch_requirements()
    except (ConnectionError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.dry_run:
        by_system = {}
        for req in reqs:
            by_system.setdefault(req.system, []).append(req)

        for system, files in sorted(by_system.items()):
            print(f"\n{system} ({len(files)} files):")
            for f in files:
                hash_info = f.md5[:12] if f.md5 else "no-hash"
                print(f"  {f.name} ({hash_info}...)")

        print(f"\nTotal: {len(reqs)} BIOS files across {len(by_system)} systems")
        return

    if args.json:
        config = scraper.generate_platform_yaml()
        print(json.dumps(config, indent=2))
        return

    if args.output:
        try:
            import yaml
        except ImportError:
            print("Error: PyYAML required", file=sys.stderr)
            sys.exit(1)

        config = scraper.generate_platform_yaml()
        with open(args.output, "w") as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        print(f"Written to {args.output}")
    else:
        by_system = {}
        for req in reqs:
            by_system.setdefault(req.system, []).append(req)
        print(f"Scraped {len(reqs)} BIOS files across {len(by_system)} systems")


if __name__ == "__main__":
    main()
