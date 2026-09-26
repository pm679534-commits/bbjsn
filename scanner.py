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

    Qeyd: Semgrep bəzən (bir qaydanın pattern-i sınıqdırsa, timeout olsa və s.)
    returncode 0/1-dən fərqli bir kod qaytarır, amma yenə də etibarlı JSON
    nəticə çıxarır (digər qaydalar problemsiz işləmiş olur). Ona görə əsas
    meyar returncode deyil, stdout-un etibarlı JSON olub-olmamasıdır.
    """
    cmd = [
        "semgrep",
        "--config", SEMGREP_RULES,
        "--config", "p/php",
        "--json",
        "--quiet",
        "--timeout", "120",
        "--max-memory", "400",
        "--jobs", "1",
        str(plugin_path),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        # Stdout etibarlı JSON deyil — bu, əsl fatal xətadır
        detail = result.stderr.strip() or result.stdout.strip() or "boş çıxış"
        raise RuntimeError(f"(exit code {result.returncode}) {detail[:800]}")

    # JSON etibarlıdırsa, nəticələri qaytarırıq. errors sahəsi varsa
    # (məs. bir qaydanın pattern-i sınıqdır), bu qismi xətadır, fatal deyil —
    # sadəcə konsola loglayırıq ki, sonradan qayda düzəldilə bilsin.
    rule_errors = data.get("errors", [])
    if rule_errors:
        for err in rule_errors:
            print(f"[semgrep qayda xəbərdarlığı] {err.get('rule_id')}: {err.get('message', '')[:200]}")

    return data.get("results", [])
