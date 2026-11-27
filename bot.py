"""Simple passive subdomain finder bot. Usage in Telegram: /subs example.com

Passive only: it asks public websites (crt.sh etc.) and never contacts the target.
Uses long polling, so it opens no ports.
"""

import asyncio
import html
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request

from telegram import Update
from telegram.constants import ParseMode
from telegram.error import NetworkError
from telegram.ext import Application, CommandHandler, ContextTypes

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
if not BOT_TOKEN:
    sys.exit("Set the TELEGRAM_BOT_TOKEN environment variable (get one from @BotFather).")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)  # its logs would contain the bot token
log = logging.getLogger("bot")

DOMAIN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
MAX_REPLY_CHARS = 3500
busy = asyncio.Semaphore(3)  # at most 3 searches at the same time

# subfinder is used automatically if it is installed (https://github.com/projectdiscovery/subfinder).
# It reads your API keys from its own config file, so no keys are needed in this code.
INSTALL_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "install_subfinder.ps1")


def find_subfinder():
    """Look on PATH, then in the folder the install script uses (PATH of a running program is not refreshed)."""
    found = shutil.which("subfinder")
    if not found and os.name == "nt":
        candidate = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "subfinder", "subfinder.exe")
        found = candidate if os.path.exists(candidate) else None
    return found


def install_subfinder_if_missing():
    """On Windows, run the PowerShell installer (it asks for administrator rights with a UAC prompt)."""
    found = find_subfinder()
    if found or os.name != "nt" or os.environ.get("AUTO_INSTALL_SUBFINDER") == "0":
        return found
    log.info("subfinder not found. Running install_subfinder.ps1 (accept the UAC prompt)...")
    try:
        subprocess.run(  # list of arguments, no shell
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", INSTALL_SCRIPT],
            check=False,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as error:
        log.warning("Could not run the installer: %r", error)
    return find_subfinder()


SUBFINDER = install_subfinder_if_missing()
# Optional: use a provider config file from another place than subfinder's default.
SUBFINDER_PROVIDER_CONFIG = os.environ.get("SUBFINDER_PROVIDER_CONFIG")
SUBFINDER_TIMEOUT = 150  # seconds; it asks many providers, so it needs longer than one website


# ---------- sources: each one turns the website's reply into a list of names ----------

def crtsh(text):
    return [n for r in json.loads(text) for n in r["name_value"].split("\n")]


def certspotter(text):
    return [n for r in json.loads(text) for n in r["dns_names"]]


def hackertarget(text):
    return [line.split(",")[0] for line in text.splitlines()]


def urlscan(text):
    return [r["page"]["domain"] for r in json.loads(text)["results"]]


def wayback(text):
    return [urllib.parse.urlparse(row[0]).hostname or "" for row in json.loads(text)[1:]]


# name -> (url, parser). {d} is replaced by the (already validated) domain.
SOURCES = {
    "crt.sh": ("https://crt.sh/?q=%25.{d}&output=json", crtsh),
    "certspotter": ("https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names", certspotter),
    "hackertarget": ("https://api.hackertarget.com/hostsearch/?q={d}", hackertarget),
    "urlscan": ("https://urlscan.io/api/v1/search/?q=domain:{d}&size=100", urlscan),
    "wayback": ("https://web.archive.org/cdx/search/cdx?url=*.{d}&output=json&fl=original&collapse=urlkey&limit=20000", wayback),
}


def download(url):
    """Download a page as text. Tries twice because these free sites are often busy."""
    for attempt in (1, 2):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "PassiveReconBot/1.0"})
            with urllib.request.urlopen(request, timeout=20) as response:
                return response.read(30 * 1024 * 1024).decode("utf-8", errors="replace")
        except Exception:
            if attempt == 2:
                raise


def keep_valid(names, domain):
    """Keep only clean hostnames that belong to the domain."""
    found = set()
    for n in names:
        n = n.strip().lower().removeprefix("*.")
        if DOMAIN_RE.match(n) and (n == domain or n.endswith("." + domain)):
            found.add(n)
    return found


def search_one_source(name, domain):
    """Return the subdomains one website knows about."""
    url, parser = SOURCES[name]
    return keep_valid(parser(download(url.format(d=domain))), domain)


async def search_subfinder(domain):
    """Run the subfinder program. It handles every provider's rate limits and API keys by itself."""
    command = [SUBFINDER, "-silent", "-d", domain]  # domain was validated, and there is no shell involved
    if SUBFINDER_PROVIDER_CONFIG:
        command += ["-pc", SUBFINDER_PROVIDER_CONFIG]

    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        output, _ = await asyncio.wait_for(process.communicate(), SUBFINDER_TIMEOUT)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        raise
    if process.returncode != 0:
        raise RuntimeError(f"subfinder exited with code {process.returncode}")
    return keep_valid(output.decode(errors="replace").splitlines(), domain)


# ---------- Telegram commands ----------

async def send(message_function, *args, **kwargs):
    """Send to Telegram. Retries up to 3 times, because a slow connection to Telegram often times out."""
    for attempt in (1, 2, 3):
        try:
            return await message_function(*args, **kwargs)
        except NetworkError:  # includes TimedOut
            if attempt == 3:
                raise
            await asyncio.sleep(2)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Send: /subs example.com\nI will list the subdomains found from public sources."
    )


async def subs_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) != 1:
        await update.message.reply_text("Usage: /subs example.com")
        return

    domain = context.args[0].strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        await update.message.reply_text("That does not look like a domain. Example: example.com")
        return

    async with busy:
        await send(update.message.reply_text, f"Searching {domain} ...")

        # Ask all sources at the same time. A failing source gives an Exception instead of a result.
        # Each website gets at most 45 seconds, so one slow website cannot block the answer.
        names = list(SOURCES)
        tasks = [asyncio.wait_for(asyncio.to_thread(search_one_source, name, domain), 45) for name in names]
        if SUBFINDER:
            names.append("subfinder")
            tasks.append(search_subfinder(domain))
        results = await asyncio.gather(*tasks, return_exceptions=True)

    subdomains, failed = set(), []
    for name, result in zip(names, results):
        if isinstance(result, Exception):
            log.warning("%s failed: %r", name, result)
            failed.append(name)
        else:
            subdomains |= result

    text = f"{domain}: {len(subdomains)} subdomains found\n"
    if failed:
        text += f"Not working right now: {', '.join(failed)}\n"
    text += "\n" + "\n".join(sorted(subdomains))

    if len(text) <= MAX_REPLY_CHARS:
        await send(update.message.reply_text, f"<pre>{html.escape(text)}</pre>", parse_mode=ParseMode.HTML)
    else:  # too long for one message, send it as a file
        await send(update.message.reply_document, document=text.encode(), filename=f"{domain}.txt")


async def on_error(update, context: ContextTypes.DEFAULT_TYPE):
    log.error("Error: %r", context.error)  # one short line instead of a huge traceback


def main():
    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .concurrent_updates(True)
        # The default Telegram timeout is about 5 seconds, which is too short on a slow connection.
        .connect_timeout(30).read_timeout(30).write_timeout(60).pool_timeout(30)
        .get_updates_connect_timeout(30).get_updates_read_timeout(30)
        .build()
    )
    app.add_handler(CommandHandler(["start", "help"], help_command))
    app.add_handler(CommandHandler("subs", subs_command))
    app.add_error_handler(on_error)
    log.info("Bot started. subfinder: %s", SUBFINDER or "not installed (using websites only)")
    app.run_polling()


if __name__ == "__main__":
    main()
