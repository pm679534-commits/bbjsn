import asyncio
import logging
import os
import shutil
from pathlib import Path

from aiogram import Bot, Dispatcher
from aiogram.filters import Command
from aiogram.types import Message, FSInputFile
from aiohttp import web
from dotenv import load_dotenv

from scanner import download_plugin, run_semgrep
from ai_triage import triage_findings
from report import build_report, save_report_file
from plugin_list import fetch_popular_plugin_slugs

load_dotenv()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError("TELEGRAM_BOT_TOKEN .env faylında tapılmadı")

logging.basicConfig(level=logging.INFO)
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

WORKDIR = Path("workdir")
WORKDIR.mkdir(exist_ok=True)

# Eyni anda yalnız 1 skan gedir — həm WordPress serverlərinə,
# həm də AI API-yə həddindən artıq yük vurmamaq üçün.
scan_lock = asyncio.Lock()

MAX_PLUGINS_PER_LIST = 15
DELAY_BETWEEN_PLUGINS_SEC = 3

# Toplu skan üçün: hər dəfə bir istifadəçiyə aid yalnız 1 aktiv bulk-skan
# (əks halda paralel bulk sorğular bir-birini əngəlləyər/qarışdırar).
MAX_BULK_PLUGINS = 50
bulk_task: asyncio.Task | None = None
bulk_cancel_requested = False


@dp.message(Command("start"))
async def cmd_start(message: Message):
    await message.answer(
        "Salam! Bu, WordPress plugin-ləri üçün statik analiz (SAST) triyaj botudur.\n\n"
        "Əmrlər:\n"
        "/scan <plugin-slug> — bir plugini skan et\n"
        "  məs: /scan contact-form-7\n"
        "/scan_list <slug1,slug2,...> — bir neçəsini ardıcıl skan et (max "
        f"{MAX_PLUGINS_PER_LIST})\n"
        "/scan_bulk <say> — wordpress.org-un ən populyar pluginlərindən "
        f"göstərdiyiniz sayda (max {MAX_BULK_PLUGINS}) ardıcıl skan edir\n"
        "  məs: /scan_bulk 20\n"
        "/stop — davam edən toplu skanı dayandırır\n\n"
        "Nə edir: rəsmi wordpress.org zip-ini yükləyir → Semgrep ilə şübhəli "
        "kod nöqtələrini tapır → hər tapıntını AI-a göndərib true/false "
        "positive olduğunu qiymətləndirdirir → sizə CSV hesabat verir.\n\n"
        "Nə ETMİR: istismar (exploit/PoC) kodu yazmır, tapıntıları avtomatik "
        "ictimai elan etmir. TRUE_POSITIVE çıxan hər şeyi özünüz təsdiqləyib "
        "məsuliyyətli açıqlama prosesindən keçirməlisiniz (bax: README.md)."
    )


@dp.message(Command("scan"))
async def cmd_scan(message: Message):
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.answer("İstifadə: /scan plugin-slug\nMəs: /scan contact-form-7")
        return
    await scan_one(message, args[1].strip())


@dp.message(Command("scan_list"))
async def cmd_scan_list(message: Message):
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.answer("İstifadə: /scan_list slug1,slug2,slug3")
        return
    slugs = [s.strip() for s in args[1].split(",") if s.strip()]
    if len(slugs) > MAX_PLUGINS_PER_LIST:
        await message.answer(
            f"Bir dəfəyə maksimum {MAX_PLUGINS_PER_LIST} plugin (wordpress.org "
            "serverlərinə hörmət üçün). Siyahını bölün."
        )
        return
    for i, slug in enumerate(slugs):
        await scan_one(message, slug)
        if i < len(slugs) - 1:
            await asyncio.sleep(DELAY_BETWEEN_PLUGINS_SEC)


async def scan_one(message: Message, slug: str) -> str:
    """
    Bir plugini skan edir. Geriyə vəziyyət qaytarır: 'ok' (tapıntı yoxdur),
    'found' (tapıntı var, hesabat göndərildi) və ya 'error'.
    Bu, /scan_bulk-un sonda xülasə verə bilməsi üçün lazımdır.
    """
    async with scan_lock:
        try:
            await message.answer(f"⬇️ {slug} yüklənir...")
            plugin_path = await download_plugin(slug, WORKDIR)
        except Exception as e:
            await message.answer(f"❌ {slug} yüklənmədi: {e}")
            return "error"

        await message.answer(f"🔍 {slug} Semgrep ilə skan olunur...")
        try:
            raw_findings = run_semgrep(plugin_path)
        except Exception as e:
            await message.answer(f"❌ Semgrep xətası: {e}")
            shutil.rmtree(plugin_path, ignore_errors=True)
            return "error"

        if not raw_findings:
            await message.answer(f"✅ {slug}: Semgrep heç bir şübhəli nöqtə tapmadı.")
            shutil.rmtree(plugin_path, ignore_errors=True)
            return "ok"

        await message.answer(
            f"🤖 {len(raw_findings)} tapıntı AI ilə yoxlanılır "
            "(yalançı xəbərdarlıq süzgəci)..."
        )
        triaged = await triage_findings(raw_findings)

        text_report = build_report(slug, triaged)
        for chunk in split_message(text_report):
            await message.answer(chunk)

        report_file = save_report_file(slug, triaged, WORKDIR)
        await message.answer_document(FSInputFile(report_file))

        # Disk yerinə qənaət üçün: plaginin açılmış kodu artıq lazım deyil,
        # yalnız CSV hesabat saxlanılır. Serverdə yer azalmasın deyə silirik.
        shutil.rmtree(plugin_path, ignore_errors=True)

        has_interesting = any(
            f["ai_verdict"] in ("TRUE_POSITIVE", "NEEDS_REVIEW") for f in triaged
        )
        return "found" if has_interesting else "ok"


@dp.message(Command("scan_bulk"))
async def cmd_scan_bulk(message: Message):
    global bulk_task, bulk_cancel_requested

    if bulk_task is not None and not bulk_task.done():
        await message.answer(
            "Artıq davam edən bir toplu skan var. Əvvəlcə /stop yazın."
        )
        return

    args = message.text.split(maxsplit=1)
    try:
        count = int(args[1].strip()) if len(args) > 1 else 10
    except ValueError:
        await message.answer("İstifadə: /scan_bulk <say>\nMəs: /scan_bulk 20")
        return

    if count < 1 or count > MAX_BULK_PLUGINS:
        await message.answer(
            f"Say 1 ilə {MAX_BULK_PLUGINS} arasında olmalıdır (AI xərci və "
            "vaxt məhdudiyyəti üçün). Daha çoxu lazımdırsa, əmri bir neçə "
            "dəfə ardıcıl işə salın."
        )
        return

    bulk_cancel_requested = False
    bulk_task = asyncio.create_task(run_bulk_scan(message, count))


async def run_bulk_scan(message: Message, count: int):
    global bulk_cancel_requested

    await message.answer(f"📡 wordpress.org-dan ən populyar {count} plugin çəkilir...")
    try:
        slugs = await fetch_popular_plugin_slugs(count)
    except Exception as e:
        await message.answer(f"❌ Plugin siyahısı çəkilmədi: {e}")
        return

    if not slugs:
        await message.answer("❌ Heç bir plugin tapılmadı.")
        return

    await message.answer(
        f"▶️ {len(slugs)} plugin ardıcıl skan olunacaq. İstənilən vaxt "
        "dayandırmaq üçün /stop yazın."
    )

    stats = {"ok": 0, "found": 0, "error": 0}
    for i, slug in enumerate(slugs):
        if bulk_cancel_requested:
            await message.answer(f"⏹ Toplu skan dayandırıldı ({i}/{len(slugs)} tamamlandı).")
            return

        await message.answer(f"— [{i + 1}/{len(slugs)}] {slug} —")
        result = await scan_one(message, slug)
        stats[result] = stats.get(result, 0) + 1

        if i < len(slugs) - 1:
            await asyncio.sleep(DELAY_BETWEEN_PLUGINS_SEC)

    await message.answer(
        f"🏁 Toplu skan bitdi.\n"
        f"Cəmi: {len(slugs)} | Təmiz: {stats['ok']} | "
        f"Diqqətəlayiq tapıntı olan: {stats['found']} | Xəta: {stats['error']}\n\n"
        "'Diqqətəlayiq tapıntı olan' pluginlərin hesabatlarını yuxarıda tapa "
        "bilərsiniz — hər birini əl ilə yoxlayın."
    )


@dp.message(Command("stop"))
async def cmd_stop(message: Message):
    global bulk_cancel_requested, bulk_task
    if bulk_task is None or bulk_task.done():
        await message.answer("Hazırda davam edən toplu skan yoxdur.")
        return
    bulk_cancel_requested = True
    await message.answer("⏳ Toplu skan cari plugindən sonra dayandırılacaq...")


def split_message(text: str, limit: int = 3500):
    lines = text.split("\n")
    chunks, current = [], ""
    for line in lines:
        if len(current) + len(line) + 1 > limit:
            chunks.append(current)
            current = ""
        current += line + "\n"
    if current:
        chunks.append(current)
    return chunks


async def health(request):
    """Render (və UptimeRobot kimi ping xidmətləri) üçün sadə HTTP cavab."""
    return web.Response(text="Bot işləyir")


async def start_web_server():
    """
    Render-in pulsuz 'Web Service' planı bir HTTP port gözləyir, yoxsa
    servisi fəaliyyətsiz sayıb yatırır. Bu, sadəcə o tələbi ödəyən boş serverdir —
    əsl iş Telegram polling-də gedir.
    """
    app = web.Application()
    app.router.add_get("/", health)
    runner = web.AppRunner(app)
    await runner.setup()
    port = int(os.getenv("PORT", 8080))
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()


async def main():
    await asyncio.gather(
        dp.start_polling(bot),
        start_web_server(),
    )


if __name__ == "__main__":
    asyncio.run(main())
