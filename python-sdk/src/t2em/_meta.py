"""SDK identity metadata — single source of the version string."""

SDK_VERSION = "0.5.0"

#: Identifying User-Agent (Cloudflare browser-integrity checks reject
#: the bare `Python-urllib` default; the ecosystem is agent-friendly,
#: so clients identify themselves — ТЗ §5.5, §8.6).
SDK_USER_AGENT = f"t2em-python-sdk/{SDK_VERSION}"
