import asyncio
import json
import shutil
import subprocess
import zipfile
from pathlib import Path

import requests

# Rəsmi wordpress.org zip endpoint-i. SVN checkout əvəzinə bunu istifadə etmək
# WP infrastrukturuna daha yüngül yükdür (tək HTTP GET, tam repo klonu deyil).
DOWNLOAD_URL = "https://downloads.wordpress.org/plugin/{slug}.latest-stable.zip"
SEMGREP_RULES = str(Path(__file__).parent / "rules" / "wp_security.yml")


async def download_plugin(slug: str, workdir: Path) -> Path:
    dest_dir = workdir / slug
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    dest_dir.mkdir(parents=True)

    zip_path = workdir / f"{slug}.zip"
    url = DOWNLOAD_URL.format(slug=slug)

    def _download():
        resp = requests.get(url, timeout=30, headers={"User-Agent": "wp-sast-triage-bot/1.0"})
        if resp.status_code == 404:
            raise ValueError(f"'{slug}' adlı plugin wordpress.org-da tapılmadı")
        resp.raise_for_status()
        zip_path.write_bytes(resp.content)

    await asyncio.to_thread(_download)

    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest_dir)
    zip_path.unlink(missing_ok=True)

    return dest_dir


def run_semgrep(plugin_path: Path) -> list[dict]:
    """
    Semgrep-i həm bizim custom WordPress qaydaları, həm də Semgrep-in
    ictimai PHP registry qaydaları ilə işlədir.
    """
    cmd = [
        "semgrep",
        "--config", SEMGREP_RULES,
        "--config", "p/php",
        "--json",
        "--quiet",
        "--timeout", "120",
        str(plugin_path),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

    # Semgrep: 0 = tapıntı yoxdur, 1 = tapıntı var (hər ikisi normal nəticədir)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr[:800] or "naməlum semgrep xətası")

    data = json.loads(result.stdout)
    return data.get("results", [])
