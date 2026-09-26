import aiohttp

WORDPRESS_API = "https://api.wordpress.org/plugins/info/1.2/"


async def fetch_popular_plugin_slugs(count: int) -> list[str]:
    """
    WordPress.org-un rəsmi plugins API-sindən aktiv quraşdırma sayına görə
    ən populyar plugin-lərin slug-larını çəkir. API bir sorğuda maksimum
    250 nəticə verir.
    """
    params = {
        "action": "query_plugins",
        "request[browse]": "popular",
        "request[per_page]": str(min(count, 250)),
        "request[page]": "1",
    }
    async with aiohttp.ClientSession() as session:
        async with session.get(
            WORDPRESS_API, params=params, timeout=aiohttp.ClientTimeout(total=30)
        ) as resp:
            resp.raise_for_status()
            data = await resp.json(content_type=None)

    plugins = data.get("plugins", [])
    return [p["slug"] for p in plugins[:count] if "slug" in p]
