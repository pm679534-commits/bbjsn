# WordPress Plugin SAST Triyaj Botu

Telegram vasitəsilə WordPress plugin-lərini toplu şəkildə yükləyib Semgrep ilə
statik analiz edən, tapıntıları Claude API ilə true/false positive olaraq
təsnif edən bot.

## Bu bot nə edir / nə etmir

**Edir:**
- wordpress.org-un rəsmi (açıq mənbəli, GPL lisenziyalı) zip endpoint-indən
  plugin kodunu yükləyir
- Semgrep ilə (custom WP qaydaları + ictimai PHP registry) şübhəli kod
  nöqtələrini axtarır: hazırlanmamış `$wpdb` sorğuları, sanitize olunmamış
  `$_GET/$_POST`, çatışan nonce/capability yoxlamaları
- Hər tapıntını AI-a göndərib real zəiflik namizədi olub-olmadığını
  qiymətləndirdirir (yalançı xəbərdarlıqları azaltmaq üçün)
- Telegram-da xülasə + yükləmə üçün tam CSV hesabat verir

**Etmirvi:**
- İstismar (exploit) kodu, PoC, payload generasiya etmir
- Tapıntıları avtomatik ictimai elan etmir və ya CVE bazasına göndərmir
- Hər hansı hücumu icra etmir — sadəcə kodu oxuyub qiymətləndirir

## Quraşdırma

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Semgrep-in CLI-i də lazımdır (yuxarıdakı pip install ilə gəlir, amma
ayrıca yoxlamaq üçün): `semgrep --version`

`.env.example` faylını `.env` adı ilə köçürün və doldurun:
```
TELEGRAM_BOT_TOKEN=...   # @BotFather-dən alınır
ANTHROPIC_API_KEY=...    # console.anthropic.com-dan alınır
```

İşə salın:
```bash
python bot.py
```

## İstifadə

Telegram-da bota:
- `/scan contact-form-7` — bir plugini skan edir
- `/scan_list slug1,slug2,slug3` — bir neçəsini ardıcıl skan edir (max 15,
  aralarında 3 saniyə gözləmə var — wordpress.org serverlərinə hörmət üçün)

## Nəticələri necə istifadə etməli — vacib

Bu bot **ilkin süzgəcdir**, son qərar deyil. `TRUE_POSITIVE` və ya
`NEEDS_REVIEW` işarəli hər tapıntını mütləq özünüz əl ilə yoxlayın:

1. Kodu tam kontekstdə oxuyun — dəyərin əvvəlki funksiyalarda artıq sanitize
   olunub-olunmadığını yoxlayın
2. Zəifliyin real olaraq istismar oluna biləcəyini təsdiqləyin
3. **Heç vaxt ictimai yaymayın** — əvvəlcə plugin müəllifinə bildirin
   (adətən readme.txt-də əlaqə var) və ya:
   - [Patchstack](https://patchstack.com/) — WordPress-ə fokuslanmış bug
     bounty və responsible disclosure platforması
   - [WPScan](https://wpscan.com/) — WordPress zəiflik bazası, tapıntı
     təqdim etmək mümkündür
   - [Wordfence Bug Bounty](https://www.wordfence.com/threat-intel/) —
     ödənişli bug bounty proqramı
4. Müəllif patch buraxdıqdan (və ya 90 gün gözlədikdən) sonra CVE üçün
   [MITRE-ə](https://cveform.mitre.org/) və ya Patchstack vasitəsilə müraciət
   edin

Məsuliyyətli açıqlama prosesi sizin CVE almağınıza da kömək edir — çünki
əksər CVE Numbering Authority-lər (CNA) tapıntının artıq müəllifə
bildirildiyini soruşur.

## Semgrep qaydaları haqqında qeyd

`rules/wp_security.yml` faylındakı qaydalar (xüsusilə nonce/capability
yoxlamaları) hevristikdir — WP-nin bütün kod strukturlarını tam əhatə
etmir və yanlış nəticələr verə bilər. Vaxt tapdıqca öz plugin
bazanız üzərində sınayıb dəqiqləşdirin.

## Etik/əməliyyat qeydləri

- Toplu skanlarda gözləmə vaxtını (`DELAY_BETWEEN_PLUGINS_SEC` in `bot.py`)
  azaltmayın — wordpress.org infrastrukturuna həddindən artıq yük vurmaqdan
  qaçının
- Kod parçaları AI API-yə göndərilir — bu, açıq mənbəli kod olduğu üçün
  məxfilik problemi yaratmır, amma bunu bilməkdə fayda var
