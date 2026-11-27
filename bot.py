import asyncio
import html
import json
import logging
import os
import re
import shutil
import sys
import urllib.parse
import urllib.request

from aiohttp import web

from telegram import Update
from telegram.constants import ParseMode
from telegram.error import NetworkError
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes
)

# ==========================================
# CONFIGURATION
# ==========================================

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")

if not BOT_TOKEN:
    sys.exit("ERROR: TELEGRAM_BOT_TOKEN is missing.")

PORT = int(os.environ.get("PORT", 10000))

MAX_REPLY_CHARS = 3500
SUBFINDER_TIMEOUT = 150

busy = asyncio.Semaphore(3)

SUBFINDER = shutil.which("subfinder")

SUBFINDER_PROVIDER_CONFIG = os.environ.get(
    "SUBFINDER_PROVIDER_CONFIG"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

logging.getLogger("httpx").setLevel(logging.WARNING)

log = logging.getLogger("bot")


# ==========================================
# DOMAIN VALIDATION
# ==========================================

DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def keep_valid(names, domain):

    found = set()

    for name in names:

        name = name.strip().lower().removeprefix("*.")

        if (
            DOMAIN_RE.fullmatch(name)
            and (name == domain or name.endswith("." + domain))
        ):
            found.add(name)

    return found


# ==========================================
# RENDER HEALTH CHECK
# ==========================================

async def health(request):

    return web.json_response({
        "status": "ok",
        "service": "telegram-subdomain-bot"
    })


async def start_health_server(app):

    health_app = web.Application()

    health_app.router.add_get("/", health)
    health_app.router.add_get("/health", health)

    runner = web.AppRunner(health_app)

    await runner.setup()

    site = web.TCPSite(
        runner,
        "0.0.0.0",
        PORT
    )

    await site.start()

    app.bot_data["health_runner"] = runner

    log.info("Health server running on 0.0.0.0:%s", PORT)


async def post_init(app):

    await start_health_server(app)


async def post_shutdown(app):

    runner = app.bot_data.get("health_runner")

    if runner:
        await runner.cleanup()

    log.info("Health server stopped.")


# ==========================================
# PASSIVE RECON SOURCES
# ==========================================

def crtsh(text):

    return [
        name
        for record in json.loads(text)
        for name in record["name_value"].split("\n")
    ]


def certspotter(text):

    return [
        name
        for record in json.loads(text)
        for name in record["dns_names"]
    ]


def hackertarget(text):

    return [
        line.split(",")[0]
        for line in text.splitlines()
    ]


def urlscan(text):

    return [
        record["page"]["domain"]
        for record in json.loads(text).get("results", [])
        if record.get("page", {}).get("domain")
    ]


def wayback(text):

    return [
        urllib.parse.urlparse(row[0]).hostname or ""
        for row in json.loads(text)[1:]
        if row
    ]


SOURCES = {

    "crt.sh": (
        "https://crt.sh/?q=%25.{d}&output=json",
        crtsh
    ),

    "certspotter": (
        "https://api.certspotter.com/v1/issuances"
        "?domain={d}&include_subdomains=true&expand=dns_names",
        certspotter
    ),

    "hackertarget": (
        "https://api.hackertarget.com/hostsearch/?q={d}",
        hackertarget
    ),

    "urlscan": (
        "https://urlscan.io/api/v1/search/?q=domain:{d}&size=100",
        urlscan
    ),

    "wayback": (
        "https://web.archive.org/cdx/search/cdx"
        "?url=*.{d}&output=json&fl=original"
        "&collapse=urlkey&limit=20000",
        wayback
    )

}


# ==========================================
# DOWNLOAD DATA
# ==========================================

def download(url):

    for attempt in (1, 2):

        try:

            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "PassiveReconBot/1.0"
                }
            )

            with urllib.request.urlopen(
                request,
                timeout=20
            ) as response:

                return response.read(
                    30 * 1024 * 1024
                ).decode(
                    "utf-8",
                    errors="replace"
                )

        except Exception:

            if attempt == 2:
                raise


def search_one_source(name, domain):

    url, parser = SOURCES[name]

    response = download(url.format(d=domain))

    return keep_valid(
        parser(response),
        domain
    )


# ==========================================
# OPTIONAL SUBFINDER
# ==========================================

async def search_subfinder(domain):

    command = [
        SUBFINDER,
        "-silent",
        "-d",
        domain
    ]

    if SUBFINDER_PROVIDER_CONFIG:

        command.extend([
            "-pc",
            SUBFINDER_PROVIDER_CONFIG
        ])

    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL
    )

    try:

        output, _ = await asyncio.wait_for(
            process.communicate(),
            timeout=SUBFINDER_TIMEOUT
        )

    except asyncio.TimeoutError:

        process.kill()
        await process.wait()
        raise

    if process.returncode != 0:

        raise RuntimeError(
            f"Subfinder exited with code {process.returncode}"
        )

    return keep_valid(
        output.decode(errors="replace").splitlines(),
        domain
    )


# ==========================================
# TELEGRAM MESSAGE RETRIES
# ==========================================

async def send(message_function, *args, **kwargs):

    for attempt in (1, 2, 3):

        try:

            return await message_function(
                *args,
                **kwargs
            )

        except NetworkError:

            if attempt == 3:
                raise

            await asyncio.sleep(2)


# ==========================================
# TELEGRAM COMMANDS
# ==========================================

async def help_command(update, context):

    await update.message.reply_text(
        "Welcome to Passive Subdomain Finder!\n\n"
        "Usage:\n"
        "/subs example.com\n\n"
        "I collect subdomains from public sources."
    )


async def subs_command(update, context):

    if len(context.args) != 1:

        await update.message.reply_text(
            "Usage: /subs example.com"
        )

        return

    domain = (
        context.args[0]
        .strip()
        .lower()
        .rstrip(".")
    )

    if not DOMAIN_RE.fullmatch(domain):

        await update.message.reply_text(
            "Invalid domain. Example: /subs example.com"
        )

        return

    async with busy:

        await send(
            update.message.reply_text,
            f"Searching {domain} ..."
        )

        names = list(SOURCES.keys())

        tasks = [
            asyncio.wait_for(
                asyncio.to_thread(
                    search_one_source,
                    name,
                    domain
                ),
                timeout=45
            )
            for name in names
        ]

        if SUBFINDER:

            names.append("subfinder")
            tasks.append(search_subfinder(domain))

        results = await asyncio.gather(
            *tasks,
            return_exceptions=True
        )

    subdomains = set()
    failed = []

    for name, result in zip(names, results):

        if isinstance(result, BaseException):

            log.warning("%s failed: %r", name, result)
            failed.append(name)

        else:

            subdomains |= result

    result_text = (
        f"{domain}: {len(subdomains)} subdomains found\n"
    )

    if failed:

        result_text += (
            "Not working right now: "
            + ", ".join(failed)
            + "\n"
        )

    result_text += "\n"
    result_text += "\n".join(sorted(subdomains))

    if len(result_text) <= MAX_REPLY_CHARS:

        await send(
            update.message.reply_text,
            f"<pre>{html.escape(result_text)}</pre>",
            parse_mode=ParseMode.HTML
        )

    else:

        await send(
            update.message.reply_document,
            document=result_text.encode("utf-8"),
            filename=f"{domain}.txt"
        )


# ==========================================
# ERROR HANDLER
# ==========================================

async def on_error(update, context):

    log.error(
        "Telegram error: %r",
        context.error
    )


# ==========================================
# MAIN APPLICATION
# ==========================================

def main():

    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .concurrent_updates(True)

        .connect_timeout(30)
        .read_timeout(30)
        .write_timeout(60)
        .pool_timeout(30)

        .get_updates_connect_timeout(30)
        .get_updates_read_timeout(30)

        .post_init(post_init)
        .post_shutdown(post_shutdown)

        .build()
    )

    app.add_handler(
        CommandHandler(
            ["start", "help"],
            help_command
        )
    )

    app.add_handler(
        CommandHandler(
            "subs",
            subs_command
        )
    )

    app.add_error_handler(on_error)

    log.info(
        "Starting bot. Subfinder: %s",
        SUBFINDER or "not installed"
    )

    app.run_polling()


if __name__ == "__main__":
    main()
