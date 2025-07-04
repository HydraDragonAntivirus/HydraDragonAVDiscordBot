#!/usr/bin/env python3

import os
import re
import json
import ipaddress
import discord
from discord.ext import commands
from functools import lru_cache

# ---------------------------------
# IP Extraction & Validation
# ---------------------------------

def is_valid_ip(ip_string):
    try:
        ip_obj = ipaddress.ip_address(ip_string)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local \
           or ip_obj.is_multicast or ip_obj.is_reserved:
            return None
        return "ipv4" if isinstance(ip_obj, ipaddress.IPv4Address) else "ipv6"
    except ValueError:
        return None


def extract_ip_and_port(text):
    found = []
    # Bracketed IPv6
    bracket_re = re.compile(
        r"\[(?P<ip>(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4})\]"
        r"(?::(?P<port>\d{1,5}))?"
    )
    # IPv4
    ipv4_re = re.compile(
        r"\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
        r"(?::(?P<port>\d{1,5}))?\b"
    )
    # Bare IPv6
    ipv6_re = re.compile(
        r"\b(?P<ip>(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4})\b"
    )

    # 1) Bracketed IPv6
    for m in bracket_re.finditer(text):
        ip = m.group('ip')
        port = m.group('port') and int(m.group('port'))
        ver = is_valid_ip(ip)
        if ver:
            found.append((ip, port, ver))
    # 2) IPv4
    for m in ipv4_re.finditer(text):
        ip = m.group('ip')
        port = m.group('port') and int(m.group('port'))
        if is_valid_ip(ip):
            found.append((ip, port, 'ipv4'))
    # 3) Bare IPv6
    for m in ipv6_re.finditer(text):
        ip = m.group('ip')
        if not any(ip == f[0] for f in found) and is_valid_ip(ip) == 'ipv6':
            found.append((ip, None, 'ipv6'))

    return found

# ---------------------------------
# Settings & Category Lists
# ---------------------------------

@lru_cache()
def load_settings():
    path = os.path.join('settings', 'settings.json')
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing settings file: {path}")
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def load_ip_list(path):
    if not path or not os.path.exists(path):
        return set()
    with open(path, encoding='utf-8') as f:
        return { line.strip().split(',',1)[0] for line in f if line.strip() }


def load_all_lists():
    s = load_settings()
    return {
        'whitelist_v4':  load_ip_list(s['WhiteListFilesIPv4']),
        'whitelist_v6':  load_ip_list(s['WhiteListFilesIPv6']),
        'phish_act_v4':  load_ip_list(s['PhishingFilesIPv4Active']),
        'phish_inact_v4':load_ip_list(s['PhishingFilesIPv4InActive']),
        'ddos_v4':       load_ip_list(s['DDoSFilesIPv4']),
        'ddos_v6':       load_ip_list(s['DDoSFilesIPv6']),
        'brute_v4':      load_ip_list(s['BruteForceFilesIPv4']),
        'spam_v4':       load_ip_list(s['SpamFilesIPv4']),
        'spam_v6':       load_ip_list(s['SpamFilesIPv6']),
        'malware_v4':    load_ip_list(s['MalwareFilesIPv4']),
        'malware_v6':    load_ip_list(s['MalwareFilesIPv6']),
    }


def categorize_ip(ip, version, lists=None):
    if lists is None:
        lists = load_all_lists()
    key = '_v4' if version == 'ipv4' else '_v6'
    # Priority order
    if ip in lists[f'whitelist{key}']:
        return 'whitelist'
    if version == 'ipv4' and ip in lists['phish_act_v4']:
        return 'phishing (active)'
    if version == 'ipv4' and ip in lists['phish_inact_v4']:
        return 'phishing (inactive)'
    if ip in lists[f'ddos{key}']:
        return 'ddos'
    if version == 'ipv4' and ip in lists['brute_v4']:
        return 'bruteforce'
    if ip in lists[f'spam{key}']:
        return 'spam'
    if ip in lists[f'malware{key}']:
        return 'malicious'
    return None

# ---------------------------------
# Discord Bot
# ---------------------------------

# Enable reading message content
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

@bot.event
async def on_ready():
    print(f'✅ Bot connected as {bot.user} (ID: {bot.user.id})')

@bot.command(name='scan', help='Extracts IPs and shows categories')
async def scan(ctx, *, text: str):
    results = extract_ip_and_port(text)
    if not results:
        return await ctx.reply('❌ No valid public IPs found.')

    lines = []
    for ip, port, version in results:
        port_suffix = f':{port}' if port else ''
        cat = categorize_ip(ip, version) or '(no category)'
        lines.append(f'• `{ip}{port_suffix}` ({version}) → **{cat}**')

    await ctx.reply('🔍 Scan results:\n' + '\n'.join(lines))

@bot.event
async def on_message(message):
    if message.author.bot:
        return
    if extract_ip_and_port(message.content):
        await message.add_reaction('🔍')
    await bot.process_commands(message)

if __name__ == '__main__':
    token = os.getenv('DISCORD_BOT_TOKEN')
    if not token:
        print('Error: set DISCORD_BOT_TOKEN environment variable')
        exit(1)
    bot.run(token)