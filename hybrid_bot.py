import discord
from discord import app_commands
import os
import json
import requests
import time
import asyncio
import logging
import random
import auto_rules_engine as token_engine
from typing import List

# ==============================
# CONFIG
# ==============================

DISCORD_TOKEN = "MTQ2MTkyNzIzNTQwMDIzNzQwOA.GDO6X3.BDV4LEiCR627q7HB6ei032dk5fgkP-6TJJeiWk"
GUILD_ID = 1461930741729591369

intents = discord.Intents.default()
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)
guild = discord.Object(id=GUILD_ID)

# Logging (so we can see crashes in the console)
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(message)s")
logger = logging.getLogger("outlook-rules-bot")

# Resolve tokens directory relative to this script.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOKENS_DIR = os.path.join(BASE_DIR, "tokens")

# Microsoft Graph config
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_TIMEOUT_SECONDS = 20
GRAPH_MAX_RETRIES = 4


def _graph_request(method: str, url: str, headers: dict, json_body: dict | None = None) -> requests.Response:
    """
    Wrapper around requests with timeouts + retries.
    Retries on transient errors and rate limits (429).
    """
    last_exc: Exception | None = None

    for attempt in range(GRAPH_MAX_RETRIES):
        try:
            resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=json_body,
                timeout=GRAPH_TIMEOUT_SECONDS,
            )

            if resp.status_code in (429, 500, 502, 503, 504):
                retry_after = resp.headers.get("Retry-After")
                if retry_after is not None:
                    try:
                        wait_s = float(retry_after)
                    except ValueError:
                        wait_s = 1.0
                else:
                    wait_s = (1.5 ** attempt) + random.random()

                logger.warning("Graph retry %s %s -> %s (wait %.2fs)", method, url, resp.status_code, wait_s)
                time.sleep(wait_s)
                continue

            return resp

        except requests.exceptions.RequestException as e:
            last_exc = e
            wait_s = (1.5 ** attempt) + random.random()
            logger.warning("Graph network error retry %s %s (wait %.2fs): %s", method, url, wait_s, e)
            time.sleep(wait_s)

    # Out of retries
    if last_exc:
        raise last_exc
    raise RuntimeError("Graph request failed without exception detail")

# ==============================
# TOKEN FILENAME HELPERS
# ==============================

def _email_to_safe_filename(email: str) -> str:
    """
    Must match the mapping used in `auth_server.py`.
    Example: a@b.com -> a_at_b_com
    """
    email_norm = email.strip().lower()
    return email_norm.replace("@", "_at_").replace(".", "_")


def _enable_rules_for_token_file(file: str, path: str) -> str:
    try:
        with open(path, "r") as f:
            token_data = json.load(f)
    except Exception as e:
        logger.exception("Failed loading token file %s: %s", path, e)
        return f"{file.replace('.json','')} → Failed (token file error)"

    token_data = _maybe_refresh_access_token(token_data, path) or token_data
    access_token = token_data.get("access_token") if token_data else None
    if not access_token:
        return f"{file.replace('.json','')} → Failed (no access token)"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    rules_url = f"{GRAPH_BASE}/me/mailFolders/inbox/messageRules"

    # Fetch rules
    try:
        rules_response = _graph_request("GET", rules_url, headers=headers)
    except Exception as e:
        logger.exception("Graph GET rules failed for %s: %s", file, e)
        return f"{file.replace('.json','')} → Failed (rules fetch error)"

    # Refresh once if unauthorized
    if rules_response.status_code == 401:
        try:
            token_data = token_engine.refresh_access_token(token_data, path)
        except Exception as e:
            logger.exception("Token refresh crashed for %s: %s", file, e)
            token_data = None

        if not token_data:
            return f"{file.replace('.json','')} → Failed (refresh failed)"

        access_token = token_data.get("access_token")
        if not access_token:
            return f"{file.replace('.json','')} → Failed (no access token after refresh)"

        headers["Authorization"] = f"Bearer {access_token}"
        try:
            rules_response = _graph_request("GET", rules_url, headers=headers)
        except Exception as e:
            logger.exception("Graph GET rules failed after refresh for %s: %s", file, e)
            return f"{file.replace('.json','')} → Failed (rules fetch error)"

    if rules_response.status_code != 200:
        return f"{file.replace('.json','')} → Failed ({rules_response.status_code})"

    try:
        rules = rules_response.json().get("value", [])
    except Exception:
        return f"{file.replace('.json','')} → Failed (bad rules response)"

    total = len(rules)
    fixed = 0
    already = 0
    enable_failed = 0
    first_failure_detail = None
    rule_lines: List[str] = []

    for rule in rules:
        rule_id = rule.get("id")
        rule_name = rule.get("displayName") or "(no displayName)"
        before = bool(rule.get("isEnabled", False))

        if not rule_id:
            continue

        try:
            if before:
                already += 1
                rule_lines.append(f"{rule_name} [{rule_id}]: {before} -> {before}")
                continue

            rule_url = f"{GRAPH_BASE}/me/mailFolders/inbox/messageRules/{rule_id}"

            def _verify_enabled() -> tuple[bool, str]:
                last_detail = ""
                for attempt in range(2):
                    try:
                        verify = _graph_request("GET", rule_url, headers=headers)
                        if verify.status_code != 200:
                            last_detail = f"verify_status={verify.status_code}"
                            enabled = False
                        else:
                            enabled = bool(verify.json().get("isEnabled", False))
                            last_detail = f"verify_isEnabled={enabled}"
                    except Exception as e:
                        last_detail = f"verify_error={type(e).__name__}"
                        enabled = False

                    if enabled:
                        return True, last_detail
                    if attempt == 0:
                        time.sleep(2)

                return False, last_detail

            update = _graph_request(
                "PATCH",
                rule_url,
                headers=headers,
                json_body={"isEnabled": True},
            )
            patch_status = update.status_code

            # If token expired mid-loop, refresh and retry once.
            if update.status_code == 401:
                try:
                    token_data = token_engine.refresh_access_token(token_data, path)
                except Exception as e:
                    logger.exception("Token refresh crashed mid-loop for %s: %s", file, e)
                    token_data = None

                access_token = token_data.get("access_token") if token_data else None
                if access_token:
                    headers["Authorization"] = f"Bearer {access_token}"
                    update = _graph_request(
                        "PATCH",
                        rule_url,
                        headers=headers,
                        json_body={"isEnabled": True},
                    )
                    patch_status = f"401->{update.status_code}"
                else:
                    patch_status = "401->no_access_token"

            verified, verify_detail = _verify_enabled()
            after = bool(verified)

            if after:
                fixed += 1
            else:
                enable_failed += 1
                if first_failure_detail is None:
                    first_failure_detail = f"rule_id={rule_id} patch_status={patch_status} {verify_detail}"

            rule_lines.append(f"{rule_name} [{rule_id}]: {before} -> {after}")

        except Exception as e:
            logger.exception("Rule enable crashed for %s rule %s: %s", file, rule_id, e)
            enable_failed += 1
            if first_failure_detail is None:
                first_failure_detail = f"rule_id={rule_id} exception={type(e).__name__}"

    email_name = file.replace(".json", "")
    # Professional plain-text report:
    # - keep it short for successful runs
    # - only show per-rule details when it helps debugging
    # Keep output clean: only show per-rule state details when something failed.
    show_rule_states = enable_failed > 0

    rule_states_preview = ""
    if show_rule_states and rule_lines:
        # Cap output so a single mailbox can't spam Discord.
        rule_states_preview = "\nRule states (first 8):\n" + "\n".join(rule_lines[:8])
        if len(rule_lines) > 8:
            rule_states_preview += "\n(…more rules exist)"

    failure_line = f"First Failure: {first_failure_detail}\n" if first_failure_detail else ""

    return (
        f"📧 Mailbox: {email_name}\n"
        f"📊 Total rules: {total}\n"
        f"✅ Enabled already: {already}\n"
        f"🔧 Enabled now: {fixed}\n"
        f"⚠️ Enable failed: {enable_failed}\n"
        + failure_line.replace("First Failure:", "❌ First failure:")
        + rule_states_preview.replace("Rule states", "🧾 Rule states")
    )

# ==============================
# CORE FUNCTION
# ==============================

def _chunk_text(text: str, max_len: int = 1900) -> List[str]:
    if len(text) <= max_len:
        return [text]

    lines = text.splitlines()
    chunks: List[str] = []
    current: List[str] = []
    current_len = 0

    for line in lines:
        # +1 accounts for the '\n' that will be inserted when joining.
        extra = len(line) + (1 if current else 0)
        if current and (current_len + extra > max_len):
            chunks.append("\n".join(current))
            current = [line]
            current_len = len(line)
        else:
            current.append(line)
            current_len += extra

    if current:
        chunks.append("\n".join(current))
    return chunks


def _maybe_refresh_access_token(token_data: dict, filepath: str) -> dict | None:
    """
    Best-effort refresh before we call Graph.
    Even if we don't refresh here, we also refresh on 401 below.
    """
    if not token_data:
        return None

    refresh_token = token_data.get("refresh_token")
    if not refresh_token:
        return token_data

    # If expires_at exists, refresh if expired.
    expires_at = token_data.get("expires_at")
    if expires_at is not None:
        try:
            if time.time() > float(expires_at):
                return token_engine.refresh_access_token(token_data, filepath)
        except (TypeError, ValueError):
            pass

    # If we can't determine expiry reliably, skip pre-refresh.
    return token_data


def enable_rules(max_accounts: int | None = None) -> str:
    results: List[str] = []

    if not os.path.exists(TOKENS_DIR):
        return "No tokens folder found."

    token_files = sorted(
        [f for f in os.listdir(TOKENS_DIR) if f.endswith(".json")]
    )
    if max_accounts is not None:
        token_files = token_files[: max_accounts]

    for file in token_files:
        path = os.path.join(TOKENS_DIR, file)
        results.append(_enable_rules_for_token_file(file, path))

    if not results:
        return "No accounts found."

    return "\n".join(results)


def enable_rules_for_single_email(email: str) -> str:
    if not os.path.exists(TOKENS_DIR):
        return "No tokens folder found."

    email_in = email.strip()

    # Accept either:
    # - real email (contains "@"), or
    # - the "safe" token filename you already see in the bot output.
    if "@" in email_in:
        safe_filename = _email_to_safe_filename(email_in)
    else:
        # Allow passing the safe token filename with or without ".json".
        safe_filename = email_in.replace(".json", "")

    token_path = os.path.join(TOKENS_DIR, f"{safe_filename}.json")
    if os.path.exists(token_path):
        return _enable_rules_for_token_file(f"{safe_filename}.json", token_path)

    # Fallback: show closest token filenames to help you choose the exact one.
    available = [f for f in os.listdir(TOKENS_DIR) if f.endswith(".json")]
    available_preview = ", ".join(available[:20]) if available else "(none)"
    return (
        f"Token not found for {email}.\n"
        f"Expected filename: {safe_filename}.json\n"
        f"Available token files: {available_preview}"
    )

# ==============================
# SLASH GROUP
# ==============================

outlook = app_commands.Group(
    name="outlook",
    description="Outlook rule management",
    guild_ids=[GUILD_ID]
)

@outlook.command(
    name="enable_one",
    description="Enable rules for one linked email"
)
async def enable_one(interaction: discord.Interaction, email: str):
    await interaction.response.defer(thinking=True)
    try:
        output = await asyncio.to_thread(enable_rules_for_single_email, email)
    except Exception as e:
        logger.exception("enable_one crashed: %s", e)
        await interaction.followup.send(f"Rules Enabler 2.0\n\nFailed: {type(e).__name__}")
        return

    header = "Rules Enabler 2.0\n\n"
    chunks = _chunk_text(output, max_len=1900 - len(header))
    max_chunks = 10
    for i, chunk in enumerate(chunks[:max_chunks]):
        prefix = header if i == 0 else ""
        try:
            await interaction.followup.send(prefix + chunk)
        except discord.HTTPException:
            break
        await asyncio.sleep(0.2)


@outlook.command(
    name="enable_five",
    description="Enable rules for up to 5 specific emails"
)
async def enable_five(
    interaction: discord.Interaction,
    email1: str,
    email2: str | None = None,
    email3: str | None = None,
    email4: str | None = None,
    email5: str | None = None,
):
    await interaction.response.defer(thinking=True)
    try:
        emails = [e for e in [email1, email2, email3, email4, email5] if e and e.strip()]
        if not emails:
            await interaction.followup.send("Rules Enabler 2.0\n\nPlease provide at least 1 email/token name.")
            return

        def _run_batch() -> str:
            return "\n\n".join(enable_rules_for_single_email(e) for e in emails)

        output = await asyncio.to_thread(_run_batch)
    except Exception as e:
        logger.exception("enable_five crashed: %s", e)
        await interaction.followup.send(f"Rules Enabler 2.0\n\nFailed: {type(e).__name__}")
        return

    header = "Rules Enabler 2.0\n\n"
    chunks = _chunk_text(output, max_len=1900 - len(header))
    max_chunks = 10
    for i, chunk in enumerate(chunks[:max_chunks]):
        prefix = header if i == 0 else ""
        try:
            await interaction.followup.send(prefix + chunk)
        except discord.HTTPException:
            break
        await asyncio.sleep(0.2)

    if len(chunks) > max_chunks:
        await interaction.followup.send("Output truncated to avoid Discord rate limits.")

tree.add_command(outlook)

# ==============================
# READY EVENT
# ==============================

@client.event
async def on_ready():
    # Remove stale commands (like older /fixrules) even if they are global.
    # Discord may cache commands, so we explicitly delete before syncing.
    fix_names = {"fixrules", "fix_rules", "fix_rule"}

    async def _delete_from_scope(scope_guild):
        try:
            if scope_guild is None:
                cmds = await tree.fetch_commands()
            else:
                cmds = await tree.fetch_commands(guild=scope_guild)
        except Exception as e:
            logger.warning("fetch_commands failed (scope=%s): %s", scope_guild, e)
            return

        deleted = 0
        for cmd in cmds:
            # Top-level command name is cmd.name, e.g. "fixrules"
            if cmd.name in fix_names:
                try:
                    await cmd.delete()
                    deleted += 1
                    logger.info("Deleted stale command: %s (scope=%s)", cmd.name, scope_guild)
                except Exception as e:
                    logger.warning("Failed deleting %s (scope=%s): %s", cmd.name, scope_guild, e)

        if deleted == 0:
            logger.info("No stale fix commands found to delete (scope=%s).", scope_guild)

    # Try deleting in both guild and global scopes.
    await _delete_from_scope(guild)
    await _delete_from_scope(None)

    await tree.sync(guild=guild)
    logger.info("Bot ready as %s", client.user)


@client.event
async def on_error(event_method, *args, **kwargs):
    # Prevent crashes from unhandled event handler exceptions.
    logger.exception("Discord event error in %s", event_method)


@client.event
async def on_app_command_error(interaction: discord.Interaction, error: Exception):
    logger.exception("App command error: %s", error)
    try:
        if interaction.response.is_done():
            await interaction.followup.send(f"Command failed: {type(error).__name__}")
        else:
            await interaction.response.send_message(f"Command failed: {type(error).__name__}", ephemeral=True)
    except Exception:
        # If Discord API errors, just log; don't crash the bot.
        pass

# ==============================
# RUN
# ==============================

client.run(DISCORD_TOKEN)