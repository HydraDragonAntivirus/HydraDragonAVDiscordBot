
#!/usr/bin/env python3

import os
import re
import json
import ipaddress
import discord
from discord.ext import commands
from functools import lru_cache
import aiohttp
from bs4 import BeautifulSoup
import socket
import tldextract
import asyncio

# ---------------------------------
# IP Extraction & Validation
# ---------------------------------

def get_my_public_ip():
    """Get the bot's public IP address"""
    try:
        import urllib.request
        with urllib.request.urlopen('https://api.ipify.org', timeout=5) as response:
            return response.read().decode('utf-8').strip()
    except:
        try:
            # Fallback method
            with urllib.request.urlopen('https://icanhazip.com', timeout=5) as response:
                return response.read().decode('utf-8').strip()
        except:
            return None

def is_valid_ip(ip_string):
    try:
        ip_obj = ipaddress.ip_address(ip_string)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local \
           or ip_obj.is_multicast or ip_obj.is_reserved:
            return None
        return "ipv4" if isinstance(ip_obj, ipaddress.IPv4Address) else "ipv6"
    except ValueError:
        return None

def should_exclude_ip(ip_string):
    """Check if an IP should be excluded from results"""
    # Get your public IP (cached)
    my_ip = get_my_public_ip()
    
    # Exclude your own IP
    if my_ip and ip_string == my_ip:
        return True

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

    for m in bracket_re.finditer(text):
        ip = m.group('ip')
        port = m.group('port') and int(m.group('port'))
        ver = is_valid_ip(ip)
        if ver and not should_exclude_ip(ip):
            found.append((ip, port, ver))
    for m in ipv4_re.finditer(text):
        ip = m.group('ip')
        port = m.group('port') and int(m.group('port'))
        if is_valid_ip(ip) and not should_exclude_ip(ip):
            found.append((ip, port, 'ipv4'))
    for m in ipv6_re.finditer(text):
        ip = m.group('ip')
        if not any(ip == f[0] for f in found) and is_valid_ip(ip) == 'ipv6' and not should_exclude_ip(ip):
            found.append((ip, None, 'ipv6'))
    return found

# ---------------------------------
# Settings & Category Lists
# ---------------------------------

@lru_cache()
def load_settings():
    path = os.path.join('settings', 'settings.json')
    if not os.path.exists(path):
        # Return default settings if file doesn't exist
        print(f"Warning: Settings file not found at {path}, using defaults")
        return {
            'WhiteListFilesIPv4': '',
            'WhiteListFilesIPv6': '',
            'PhishingFilesIPv4Active': '',
            'PhishingFilesIPv4InActive': '',
            'DDoSFilesIPv4': '',
            'DDoSFilesIPv6': '',
            'BruteForceFilesIPv4': '',
            'SpamFilesIPv4': '',
            'SpamFilesIPv6': '',
            'MalwareFilesIPv4': '',
            'MalwareFilesIPv6': '',
        }
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def load_ip_list(path):
    if not path or not os.path.exists(path):
        return set()
    try:
        with open(path, encoding='utf-8') as f:
            return { line.strip().split(',',1)[0] for line in f if line.strip() }
    except Exception as e:
        print(f"Error loading IP list from {path}: {e}")
        return set()


def load_all_lists():
    s = load_settings()
    return {
        'whitelist_v4':  load_ip_list(s.get('WhiteListFilesIPv4', '')),
        'whitelist_v6':  load_ip_list(s.get('WhiteListFilesIPv6', '')),
        'phish_act_v4':  load_ip_list(s.get('PhishingFilesIPv4Active', '')),
        'phish_inact_v4':load_ip_list(s.get('PhishingFilesIPv4InActive', '')),
        'ddos_v4':       load_ip_list(s.get('DDoSFilesIPv4', '')),
        'ddos_v6':       load_ip_list(s.get('DDoSFilesIPv6', '')),
        'brute_v4':      load_ip_list(s.get('BruteForceFilesIPv4', '')),
        'spam_v4':       load_ip_list(s.get('SpamFilesIPv4', '')),
        'spam_v6':       load_ip_list(s.get('SpamFilesIPv6', '')),
        'malware_v4':    load_ip_list(s.get('MalwareFilesIPv4', '')),
        'malware_v6':    load_ip_list(s.get('MalwareFilesIPv6', '')),
    }


def categorize_ip(ip, version, lists=None):
    if lists is None:
        lists = load_all_lists()
    key = '_v4' if version == 'ipv4' else '_v6'
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
# Heuristic URL Scanner
# ---------------------------------

async def heuristic_scan_url(url: str):
    try:
        lists = load_all_lists()
        whitelist = lists['whitelist_v4'] | lists['whitelist_v6']
        malicious = lists['phish_act_v4'] | lists['phish_inact_v4']
        found_ips = set()
        flags = {'whitelisted': [], 'malicious': [], 'unknown': []}

        if not url.startswith(('http://','https://')):
            url = 'http://' + url
        
        # Set up session with proper headers and timeout
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
            try:
                async with session.get(url, allow_redirects=True) as resp:
                    if resp.status != 200:
                        return {'error': f'HTTP {resp.status} error for {url}'}
                    html = await resp.text()
            except asyncio.TimeoutError:
                return {'error': f'Timeout while fetching {url}'}
            except Exception as e:
                return {'error': f'Failed to fetch {url}: {str(e)}'}

        # extract domain IP
        td = tldextract.extract(url)
        host = f"{td.subdomain}.{td.domain}.{td.suffix}".strip('.')
        if host and host != '.':
            try:
                ip = socket.gethostbyname(host)
                found_ips.add(ip)
            except Exception as e:
                print(f"Could not resolve {host}: {e}")

        # parse links
        soup = BeautifulSoup(html, 'html.parser')
        for tag in soup.find_all(['a','script','img','link']):
            src = tag.get('href') or tag.get('src')
            if not src:
                continue
            
            # Handle relative URLs
            if src.startswith('//'):
                src = 'http:' + src
            elif src.startswith('/'):
                continue  # Skip relative paths
            elif not src.startswith(('http://', 'https://')):
                continue  # Skip other protocols
                
            td2 = tldextract.extract(src)
            host2 = f"{td2.subdomain}.{td2.domain}.{td2.suffix}".strip('.')
            if host2 and host2 != '.':
                try:
                    ip2 = socket.gethostbyname(host2)
                    found_ips.add(ip2)
                except Exception:
                    continue

        # classify
        for ip in found_ips:
            if should_exclude_ip(ip):
                continue  # Skip your own IP
            elif ip in whitelist:
                flags['whitelisted'].append(ip)
            elif ip in malicious:
                flags['malicious'].append(ip)
            else:
                flags['unknown'].append(ip)
        
        return flags
    except Exception as e:
        return {'error': f'Unexpected error: {str(e)}'}

# ---------------------------------
# Discord Bot
# ---------------------------------

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

@bot.event
async def on_ready():
    print(f'✅ Bot connected as {bot.user} (ID: {bot.user.id})')
    print(f'Bot is in {len(bot.guilds)} guilds')

@bot.command(name='scan', help='Extracts IPs from text and shows their categories')
async def scan_command(ctx, *, text: str = None):
    """Scan text for IPs and categorize them"""
    if text is None:
        await ctx.reply('❌ Please provide text to scan. Usage: `!scan <text with IPs>`')
        return
    
    try:
        results = extract_ip_and_port(text)
        if not results:
            await ctx.reply('❌ No valid public IPs found in the provided text.')
            return
        
        lines = []
        for ip, port, version in results:
            suffix = f':{port}' if port else ''
            cat = categorize_ip(ip, version) or '(no category)'
            lines.append(f'• `{ip}{suffix}` ({version}) → **{cat}**')
        
        response = '🔍 **IP Scan Results:**\n' + '\n'.join(lines)
        await ctx.reply(response)
    except Exception as e:
        await ctx.reply(f'❌ Error during scan: {str(e)}')

@bot.command(name='scanurl', help='Visits a URL, extracts linked IPs, and classifies them')
async def scanurl_command(ctx, url: str = None):
    """Scan a URL for associated IPs and classify them"""
    if url is None:
        await ctx.reply('❌ Please provide a URL to scan. Usage: `!scanurl <URL>`')
        return
    
    # Send initial message
    msg = await ctx.reply(f'🔍 Scanning URL: `{url}`...')
    
    try:
        result = await heuristic_scan_url(url)
        
        if 'error' in result:
            await msg.edit(content=f"❌ {result['error']}")
            return
        
        response = f"**🔍 URL Scan Results for:** `{url}`\n\n"
        
        if result['whitelisted']:
            response += f"✅ **Whitelisted IPs:** `{', '.join(result['whitelisted'])}`\n"
        if result['malicious']:
            response += f"🚫 **Malicious IPs:** `{', '.join(result['malicious'])}`\n"
        if result['unknown']:
            response += f"❓ **Unknown IPs:** `{', '.join(result['unknown'])}`\n"
        
        if not any([result['whitelisted'], result['malicious'], result['unknown']]):
            response += "ℹ️ No IPs found or resolved from this URL."
        
        await msg.edit(content=response)
    except Exception as e:
        await msg.edit(content=f'❌ Error during URL scan: {str(e)}')

@bot.event
async def on_message(message):
    # Ignore bot messages
    if message.author.bot:
        return
    
    # Check if message contains IPs and add reaction
    try:
        if extract_ip_and_port(message.content):
            await message.add_reaction('🔍')
    except Exception as e:
        print(f"Error adding reaction: {e}")
    
    # Process commands
    await bot.process_commands(message)

@bot.event
async def on_command_error(ctx, error):
    """Handle command errors"""
    if isinstance(error, commands.CommandNotFound):
        return  # Ignore unknown commands
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.reply(f'❌ Missing required argument. Use `!help {ctx.command}` for usage info.')
    else:
        print(f'Command error: {error}')
        await ctx.reply(f'❌ An error occurred: {str(error)}')

if __name__ == '__main__':
    token = os.getenv('DISCORD_BOT_TOKEN')
    if not token:
        print('❌ Error: Set DISCORD_BOT_TOKEN environment variable')
        exit(1)
    
    try:
        bot.run(token)
    except Exception as e:
        print(f'❌ Failed to start bot: {e}')
        exit(1)