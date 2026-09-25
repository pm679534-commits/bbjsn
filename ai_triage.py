import asyncio
import os

from anthropic import AsyncAnthropic

# Rəsmi Anthropic API-dən fərqli bir endpoint (proksi/relay xidməti,
# özünüzün host etdiyiniz gateway və s.) istifadə edirsinizsə,
# ANTHROPIC_BASE_URL-i .env-də təyin edin. Boş buraxsanız SDK avtomatik
# olaraq rəsmi https://api.anthropic.com ünvanına gedir.
_base_url = os.getenv("ANTHROPIC_BASE_URL") or None

client = AsyncAnthropic(
    api_key=os.getenv("ANTHROPIC_API_KEY"),
    base_url=_base_url,
)

# Bəzi proksi/relay xidmətləri model adını fərqli formatda gözləyir
# (məs. "anthropic/claude-sonnet-4-6" kimi). Lazım gələrsə .env-də dəyişin.
MODEL_NAME = os.getenv("ANTHROPIC_MODEL") or "claude-sonnet-4-6"

SYSTEM_PROMPT = """Sən WordPress plugin kodunu nəzərdən keçirən təhlükəsizlik \
auditorusan. Sənə Semgrep-in tapdığı BİR statik analiz nəticəsi (qayda + kod \
parçası) veriləcək.

Sənin işin: bu konkret kod parçasında real, istismar oluna bilən zəiflik \
riski olub-olmadığını qiymətləndirmək.

QADAĞALAR:
- Heç bir istismar (exploit) kodu, payload, ya da PoC yazma.
- Heç bir hücum ssenarisi addım-addım təsvir etmə.
- Yalnız qiymətləndirmə və qısa texniki əsaslandırma ver.

Cavabını YALNIZ bu formatda ver, başqa heç nə yazma:
VERDICT: TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_REVIEW
REASON: (maksimum 2 cümlə)

Qiymətləndirmə meyarları:
- Dəyər artıq sanitize/escape olunubsa (məs. sanitize_text_field, absint, \
esc_sql, $wpdb->prepare, intval) → çox güman FALSE_POSITIVE.
- User input (istifadəçi girişi) filtrsiz SQL sorğusuna, fayl yoluna, \
shell əmrinə və ya birbaşa output-a gedirsə → TRUE_POSITIVE.
- Kontekst kifayət deyilsə və ya funksiya çağırışının tam zənciri görünmürsə \
→ NEEDS_REVIEW."""


async def triage_one(finding: dict) -> dict:
    path = finding.get("path", "naməlum")
    start_line = finding.get("start", {}).get("line", "?")
    end_line = finding.get("end", {}).get("line", "?")
    rule_id = finding.get("check_id", "unknown-rule")
    snippet = finding.get("extra", {}).get("lines", "")[:1500]
    rule_message = finding.get("extra", {}).get("message", "")

    user_msg = (
        f"Fayl: {path}\n"
        f"Sətir: {start_line}-{end_line}\n"
        f"Semgrep qaydası: {rule_id}\n"
        f"Qaydanın izahı: {rule_message}\n\n"
        f"Kod parçası:\n```php\n{snippet}\n```"
    )

    try:
        resp = await client.messages.create(
            model=MODEL_NAME,
            max_tokens=200,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
        text = "".join(b.text for b in resp.content if b.type == "text")
    except Exception as e:
        return {**finding, "ai_verdict": "ERROR", "ai_reason": f"AI çağırışı uğursuz: {e}"}

    verdict = "NEEDS_REVIEW"
    reason = text.strip()
    for line in text.splitlines():
        upper = line.upper()
        if upper.startswith("VERDICT:"):
            verdict = line.split(":", 1)[1].strip().upper()
        elif upper.startswith("REASON:"):
            reason = line.split(":", 1)[1].strip()

    if verdict not in ("TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW"):
        verdict = "NEEDS_REVIEW"

    return {**finding, "ai_verdict": verdict, "ai_reason": reason}


async def triage_findings(findings: list[dict], concurrency: int = 3) -> list[dict]:
    """
    concurrency məhdudlaşdırılıb ki, API rate limit-lərinə dəymə riski azalsın.
    """
    sem = asyncio.Semaphore(concurrency)

    async def _wrapped(f):
        async with sem:
            return await triage_one(f)

    return await asyncio.gather(*(_wrapped(f) for f in findings))
