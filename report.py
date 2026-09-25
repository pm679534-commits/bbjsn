import csv
from pathlib import Path


def build_report(slug: str, triaged: list[dict]) -> str:
    tp = [f for f in triaged if f["ai_verdict"] == "TRUE_POSITIVE"]
    review = [f for f in triaged if f["ai_verdict"] == "NEEDS_REVIEW"]
    fp = [f for f in triaged if f["ai_verdict"] == "FALSE_POSITIVE"]
    err = [f for f in triaged if f["ai_verdict"] == "ERROR"]

    lines = [
        f"📋 Hesabat: {slug}",
        f"Cəmi: {len(triaged)} | 🔴 TRUE_POSITIVE: {len(tp)} | "
        f"🟡 NEEDS_REVIEW: {len(review)} | 🟢 FALSE_POSITIVE: {len(fp)}"
        + (f" | ⚠️ ERROR: {len(err)}" if err else ""),
        "",
    ]

    for f in tp + review:
        lines.append(
            f"[{f['ai_verdict']}] {f.get('path')}:{f.get('start', {}).get('line')}\n"
            f"Qayda: {f.get('check_id')}\n"
            f"AI qeydi: {f.get('ai_reason')}\n"
        )

    if not (tp or review):
        lines.append("AI heç bir tapıntını real zəiflik namizədi kimi qiymətləndirmədi.")

    lines.append(
        "\n⚠️ Bu, avtomatik ilkin süzgəcdir, son qərar deyil. TRUE_POSITIVE və "
        "NEEDS_REVIEW nəticələrini əl ilə yoxlayın. Zəiflik təsdiqlənərsə, "
        "ictimai elan etmədən əvvəl plugin müəllifinə və ya Patchstack/WPScan-a "
        "məsuliyyətli şəkildə bildirin."
    )
    return "\n".join(lines)


def save_report_file(slug: str, triaged: list[dict], workdir: Path) -> Path:
    out_path = workdir / f"{slug}_report.csv"
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["file", "line", "rule", "ai_verdict", "ai_reason"])
        for finding in triaged:
            writer.writerow([
                finding.get("path"),
                finding.get("start", {}).get("line"),
                finding.get("check_id"),
                finding.get("ai_verdict"),
                finding.get("ai_reason"),
            ])
    return out_path
