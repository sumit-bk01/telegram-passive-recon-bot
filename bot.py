"""Simple passive subdomain finder bot. Usage in Telegram: /subs example.com

Passive only: it asks public websites (crt.sh etc.) and never contacts the target.
Uses long polling. When the PORT variable is set (Render web service) it also serves a tiny /health page.
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
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from telegram import Update
from telegram.constants import ParseMode
from telegram.error import NetworkError, RetryAfter
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
if not BOT_TOKEN:
    sys.exit("Set the TELEGRAM_BOT_TOKEN environment variable (get one from @BotFather).")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)  # its logs would contain the bot token
log = logging.getLogger("bot")

DOMAIN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
MAX_REPLY_CHARS = 3500
MAX_UPLOAD_BYTES = 4 * 1024 * 1024  # uploaded host lists bigger than 4 MB are refused
MAX_UPLOAD_HOSTS = 50000
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

# When subfinder is installed these overloaded websites are not needed (subfinder already uses
# crt.sh, Wayback and many more, and handles their limits). Set USE_WEBSITES=1 to query them anyway.
if SUBFINDER and os.environ.get("USE_WEBSITES") != "1":
    SOURCES = {}


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


async def gather_subdomains(domain):
    """Ask all sources at the same time. Returns (subdomains, names of the sources that failed).
    Each website gets at most 45 seconds, so one slow website cannot block the answer."""
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
    return subdomains, failed


# ---------- live check with httpx (ProjectDiscovery, Go): https://github.com/projectdiscovery/httpx ----------
# NOTE: unlike /subs, this DOES send HTTP requests to the target hosts. Only use it on domains you may test.

HTTPX_STATUS_CODES = "200,403"  # only these status codes count as "live"
HTTPX_TIMEOUT = 900  # seconds for the whole run (large uploaded lists need longer)
HTTPX_LINE_RE = re.compile(r"^(https?://\S+)\s+\[(\d{3})\]")


def find_httpx():
    """Find the Go httpx. HTTPX_PATH wins. The Go bin folder is checked too, because `go install` puts it there.
    (The Python 'httpx' package that the Telegram library uses is a different program.)"""
    explicit = os.environ.get("HTTPX_PATH")
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    found = shutil.which("httpx")
    if found:
        return found
    go_bin = os.path.join(os.environ.get("GOPATH") or os.path.join(os.path.expanduser("~"), "go"), "bin")
    candidate = os.path.join(go_bin, "httpx.exe" if os.name == "nt" else "httpx")
    return candidate if os.path.isfile(candidate) else None


HTTPX = find_httpx()


async def probe_live(hosts, live):
    """Run httpx on the hostnames and add {url: status} for the ones answering 200 or 403 to `live`
    while httpx is still running. Returns True if httpx finished, False if it hit HTTPX_TIMEOUT
    (then `live` holds the partial results found so far)."""
    # Hostnames were validated by keep_valid(); there is no shell and they go in through stdin.
    # -follow-redirects: google.com answers 301 -> www.google.com. Without it only the 301 is seen and the
    # host is dropped, because the filter keeps only 200/403 (the status of the final page is used).
    command = [HTTPX, "-silent", "-no-color", "-status-code", "-match-code", HTTPX_STATUS_CODES,
               "-follow-redirects", "-max-redirects", "5",
               "-timeout", "7", "-retries", "0", "-threads", "100", "-rate-limit", "300"]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )

    async def feed():
        process.stdin.write("\n".join(sorted(hosts)).encode())
        await process.stdin.drain()
        process.stdin.close()

    async def read():
        async for raw in process.stdout:
            match = HTTPX_LINE_RE.match(raw.decode(errors="replace").strip())
            if match:
                live[match.group(1)] = match.group(2)

    finished = True
    try:
        await asyncio.wait_for(asyncio.gather(feed(), read()), HTTPX_TIMEOUT)
        await process.wait()
        if process.returncode != 0:
            raise RuntimeError(f"httpx exited with code {process.returncode}")
    except asyncio.TimeoutError:
        finished = False
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
    return finished


# ---------- Telegram commands ----------

SEND_TRIES = 8


async def send(message_function, *args, **kwargs):
    """Send to Telegram. Retries up to 8 times with growing waits, because a slow connection often times out.
    Obeys Telegram's "retry after" (flood limit) answer. If it still fails, it is logged, None is returned
    and the bot keeps running."""
    for attempt in range(1, SEND_TRIES + 1):
        try:
            return await message_function(*args, **kwargs)
        except RetryAfter as error:
            wait = error.retry_after
            wait = wait.total_seconds() if hasattr(wait, "total_seconds") else wait
            log.warning("Telegram asked to wait %s s (try %d/%d)", wait, attempt, SEND_TRIES)
            await asyncio.sleep(wait + 1)
        except NetworkError as error:  # includes TimedOut
            log.warning("Telegram send failed (try %d/%d): %r", attempt, SEND_TRIES, error)
            await asyncio.sleep(min(3 * attempt, 20))
    return None


def split_chunks(text, limit=MAX_REPLY_CHARS):
    """Split text into pieces of at most `limit` characters, breaking only between lines."""
    chunks, current = [], ""
    for line in text.splitlines():
        line = line[:limit]  # a single line can never be longer than a message
        if current and len(current) + len(line) + 1 > limit:
            chunks.append(current)
            current = ""
        current = f"{current}\n{line}" if current else line
    if current:
        chunks.append(current)
    return chunks


async def reply_text_or_file(update: Update, text, filename):
    message = update.effective_message
    if len(text) <= MAX_REPLY_CHARS:
        await send(message.reply_text, f"<pre>{html.escape(text)}</pre>", parse_mode=ParseMode.HTML)
        return

    # Too long for one message: send it as a file. Uploads get much longer timeouts than small messages.
    sent = await send(message.reply_document, document=text.encode(), filename=filename,
                      read_timeout=180, write_timeout=180, connect_timeout=30, pool_timeout=30)
    if sent:
        return

    # The upload kept failing: send the same text as several plain messages (no HTML, so no characters can break it).
    log.warning("File upload failed, sending the result as text messages instead")
    for number, chunk in enumerate(split_chunks(text), 1):
        if not await send(message.reply_text, chunk):
            log.error("Could not deliver part %d of the result", number)
            break


def parse_domain_argument(context):
    """Return the validated domain from the command arguments, or None."""
    if len(context.args) != 1:
        return None
    domain = context.args[0].strip().lower().rstrip(".")
    return domain if DOMAIN_RE.match(domain) else None


def hosts_from_text(text):
    """Pick valid hostnames from an uploaded list. Accepts one host or URL per line, and also the
    .txt file the bot sends for long /subs results (its header lines are ignored)."""
    hosts = set()
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        token = parts[0].strip().lower()
        if "://" in token:
            token = urllib.parse.urlparse(token).hostname or ""
        token = token.removeprefix("*.")
        if DOMAIN_RE.match(token):
            hosts.add(token)
    return hosts


async def hosts_from_document(document):
    """Download a Telegram document and return (hosts, error message)."""
    if document.file_size and document.file_size > MAX_UPLOAD_BYTES:
        return None, "That file is too big (limit 4 MB)."
    telegram_file = await document.get_file()
    data = await telegram_file.download_as_bytearray()
    hosts = hosts_from_text(bytes(data[:MAX_UPLOAD_BYTES]).decode("utf-8", errors="replace"))
    if not hosts:
        return None, "I found no valid hostnames in that file. Use one subdomain per line."
    if len(hosts) > MAX_UPLOAD_HOSTS:
        return None, f"Too many hosts (limit {MAX_UPLOAD_HOSTS})."
    return hosts, None


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text(
        "Send: /subs example.com\nI will list the subdomains found from public sources.\n\n"
        "Send: /check_live example.com\nI will find the subdomains and list only the URLs that answer "
        "with status 200 or 403 (checked with httpx).\n\n"
        "Or upload a .txt file of subdomains (one per line, max 4 MB) with the caption /check_live, "
        "or reply to a file with /check_live."
    )


async def subs_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) != 1:
        await update.effective_message.reply_text("Usage: /subs example.com")
        return

    domain = parse_domain_argument(context)
    if not domain:
        await update.effective_message.reply_text("That does not look like a domain. Example: example.com")
        return

    async with busy:
        await send(update.effective_message.reply_text, f"Searching {domain} ...")
        subdomains, failed = await gather_subdomains(domain)

    text = f"{domain}: {len(subdomains)} subdomains found\n"
    if failed:
        text += f"Not working right now: {', '.join(failed)}\n"
    text += "\n" + "\n".join(sorted(subdomains))
    await reply_text_or_file(update, text, f"{domain}.txt")


async def check_live_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/check_live example.com, or a file upload with the caption /check_live, or a reply to a file."""
    if not HTTPX:
        await update.effective_message.reply_text(
            "httpx (ProjectDiscovery) is not installed. Install it with:\n"
            "go install github.com/projectdiscovery/httpx/cmd/httpx@latest\n"
            "or set HTTPX_PATH to its location."
        )
        return

    message = update.effective_message
    document = message.document or (message.reply_to_message.document if message.reply_to_message else None)
    domain = None if document else parse_domain_argument(context)

    if not document and not domain:
        if context.args:
            await message.reply_text("That does not look like a domain. Example: example.com")
        else:
            await message.reply_text(
                "Usage: /check_live example.com\n"
                "Or upload a .txt file of subdomains with the caption /check_live."
            )
        return

    async with busy:
        failed = []
        if document:
            hosts, error = await hosts_from_document(document)
            if error:
                await send(message.reply_text, error)
                return
            label, filename = "uploaded list", "uploaded-live.txt"
            await send(message.reply_text, f"Checking {len(hosts)} hosts from your file ...")
        else:
            await send(message.reply_text, f"Finding subdomains of {domain}, then checking which are live ...")
            hosts, failed = await gather_subdomains(domain)
            label, filename = domain, f"{domain}-live.txt"
            if not hosts:
                await send(message.reply_text, f"{domain}: no subdomains found.")
                return
            await send(message.reply_text, f"Found {len(hosts)} subdomains. Checking which are live "
                                           f"(can take several minutes) ...")
        live = {}
        try:
            finished = await probe_live(hosts, live)
        except Exception as error:
            log.warning("httpx failed: %r", error)
            await send(message.reply_text, "The live check failed. Try again later.")
            return

    text = f"{label}: {len(live)} live (status {HTTPX_STATUS_CODES}) out of {len(hosts)} hosts\n"
    if not finished:
        text += f"Stopped after {HTTPX_TIMEOUT // 60} minutes. This is a partial result.\n"
    if failed:
        text += f"Not working right now: {', '.join(failed)}\n"
    text += "\n" + "\n".join(f"{url} [{code}]" for url, code in sorted(live.items()))
    await reply_text_or_file(update, text, filename)


async def on_error(update, context: ContextTypes.DEFAULT_TYPE):
    # Network trouble talking to Telegram is temporary. The bot keeps running and retries by itself.
    if isinstance(context.error, NetworkError):
        log.warning("Network problem with Telegram (temporary): %r", context.error)
    else:
        log.error("Error: %r", context.error)  # one short line instead of a huge traceback


# ---------- health endpoint so Render sees an open port (an external pinger keeps the service awake) ----------

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()

    def log_message(self, *args):  # keep the logs quiet
        pass


def start_health_server():
    """Serves "ok" on $PORT. Does nothing when PORT is not set (e.g. on your own PC)."""
    port = os.environ.get("PORT")
    if not port or not port.isdigit():
        return
    # SECURITY EXCEPTION (approved by the bot owner): Render only detects services bound to 0.0.0.0.
    # The endpoint is read-only, takes no input and returns a fixed 2-byte reply.
    server = HTTPServer(("0.0.0.0", int(port)), HealthHandler)
    log.info("Health server listening on port %s", port)
    threading.Thread(target=server.serve_forever, daemon=True).start()


def main():
    start_health_server()
    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .concurrent_updates(True)
        # The default Telegram timeout is about 5 seconds, which is too short on a slow connection.
        # Sending replies and receiving messages use separate connections, so one cannot stall the other.
        .connect_timeout(30).read_timeout(30).write_timeout(60).pool_timeout(30)
        .get_updates_connect_timeout(30).get_updates_read_timeout(30)
        .get_updates_write_timeout(30).get_updates_pool_timeout(30)
        .build()
    )
    app.add_handler(CommandHandler(["start", "help"], help_command))
    app.add_handler(CommandHandler("subs", subs_command))
    app.add_handler(CommandHandler("check_live", check_live_command))
    # A file sent with the caption "/check_live" (CommandHandler does not look at captions).
    app.add_handler(MessageHandler(filters.Document.ALL & filters.CaptionRegex(r"^/check_live(@\w+)?(\s|$)"),
                                   check_live_command))
    app.add_error_handler(on_error)
    log.info("Bot started. subfinder: %s, httpx: %s", SUBFINDER or "not installed (using websites only)",
             HTTPX or "not installed (/check_live disabled)")
    app.run_polling()


if __name__ == "__main__":
    main()
