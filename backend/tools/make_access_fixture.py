#!/usr/bin/env python3
"""Builds the parser test fixture from real access.log files, anonymizing every selected line.

The repository is public, so real addresses and names are passed as arguments and must never be
written into this file or the fixture. The fixture is written only if the leak checks pass.

Example:
    python3 -I logEngine/tools/make_access_fixture.py \
        --server-ip 203.0.113.50 --server-name www.example.net --reverse-dns host-50.isp.example.net \
        --output logEngine/Schiza.LogEngine.Tests/Fixtures/access-sample.txt \
        access.log access.log-20261104

Files are searched in the given order and the first matching line is used for each label.
"""
import argparse
import re
import sys

SERVER_IP_FAKE = '192.0.2.1'
SERVER_NAME_FAKE = 'server.example.org'
REVERSE_DNS_FAKE = '192.0.2.1.ipv4.isp.example.net'
CLIENT_RANGE_FAKE = '198.51.100.'
ALLOWED_IP_PREFIXES = ('192.0.2.', CLIENT_RANGE_FAKE)

HEADER = [
    '# Real access.log lines, anonymized: client and server addresses use RFC 5737 ranges,',
    '# the server name uses example.org. Everything else is byte for byte as Apache logged it.',
    '# Each line is preceded by its label, used by the tests to refer to it.',
    '',
]

# label -> what the line must contain: substrings ({ip} and {name} stand for the server) or regexes.
SELECT = [
    # well-formed requests
    ('new-format-tls13', [re.compile(r'TLSv1\.3 \d+ \S+$')]),
    ('get-tls13-browser-ua', ['GET /wp-login.php HTTP/1.1', 'TLSv1.3', '"-" "Mozilla']),
    ('post-tls13', ['POST /xmlrpc.php HTTP/1.1', 'TLSv1.3']),
    ('get-plain-zgrab', ['GET / HTTP/1.1" 200 1336', 'zgrab', ':80 -']),
    ('get-tls13-referer-ip', ['GET /favicon.ico', '"https://{ip}/"', 'TLSv1.3']),
    ('get-referer-self-env', ['GET /.env HTTP/1.1', '"http://{name}/.env"']),
    ('get-tls12', ['" 404 ', 'TLSv1.2']),
    ('host-ip-port', ['GET /SDK/webLanguage', '"{ip}:80"']),
    ('head', ['"HEAD /']),
    ('options', ['"OPTIONS /']),
    ('redirect-301', ['" 301 ', '"{name}" {name}:80 -', 'l9scan']),
    ('http10-host-dash-mozi', ['GET /setup.cgi?', 'HTTP/1.0', 'wget+http://']),
    ('nonstandard-method-501', ['"UEQQ / HTTP/1.1" 501']),
    ('query-rest-route', ['GET /?rest_route=/wp/v2/users/', '" 200 ', 'TLSv1.3']),
    ('l9scan-debug-panel', ['GET /debug/default/view?panel=config', 'l9scan', 'TLSv1.3']),
    ('git-config', ['GET /.git/config', 'TLSv1.3']),
    ('percent-encoded-path', ['GET /%E2%9D%A4.php']),
    ('path-traversal-encoded', ['POST /cgi-bin/.%2e/.%2e/', '" 400 ']),
    ('double-percent-encoded', ['POST /cgi-bin/%%32%65%%32%65/']),
    ('php-cgi-argument-injection', ['POST /?%ADd+allow_url_include', '" 200 ']),
    ('php-cgi-double-encoded', ['POST /index.php?%25ADd+allow_url_include']),
    ('escaped-backslash', ['GET /index.php?s=/index/\\\\think\\\\app']),
    ('escaped-quote', ['<?echo(md5(\\"hi\\"));?>']),
    ('ua-aiohttp', ['Python/3.11 aiohttp']),
    ('ua-go-client', ['"Go-http-client/1.1"']),
    ('ua-dash', ['"GET /', '"-" "-" ', '.php HTTP/1.1" 404']),
    # garbage instead of a request line
    ('tls-hello-short', ['"\\x16\\x03\\x01" 400']),
    ('tls-hello-4-bytes', ['"\\x16\\x03\\x01\\x02" 400']),
    ('tls-hello-long', ['"\\x16\\x03\\x01\\x01\\x0c\\x01" 400']),
    ('tls-hello-printable-byte', ['"\\x16\\x03\\x03\\x02b\\x01" 400']),
    ('single-control-byte', ['"\\x03" 400']),
    ('newline-only', ['"\\n" 400']),
    ('weblogic-t3-over-tls', ['"t3 12.1.2\\n" 400', 'TLSv1.3']),
    ('leakix-plain', ['"LEAKIX" 400', ':80 -']),
    ('leakix-tls', ['"LEAKIX" 400', 'TLSv1.3']),
    ('ssh-banner', ['"SSH-2.0-probe" 400']),
    # no request line at all
    ('timeout-plain-zero-bytes', ['"-" 408 0 ', ':80 -']),
    ('timeout-tls', ['"-" 408 5024 ', 'TLSv1.3']),
    ('timeout-tls-other-size', ['"-" 408 5040 ', 'TLSv1.3']),
]

IPV4 = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\d)')
LAN_CLIENT = re.compile(r'^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.)')
QUOTED = r'"(?:[^"\\]|\\.)*"'
# client, ident..time, request, status and size, referer, separator, user agent, the rest
FIELDS = re.compile(rf'^(\S+)( \S+ \S+ \[[^\]]+\] )({QUOTED})( \S+ \S+ )({QUOTED})( )({QUOTED})(.*)$')
UNIQUE_ID = re.compile(r' (?:TLSv\S+|-) \d+ (\S+)$')
UNIQUE_ID_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@-'


def l9scan_token(ip):
    """The l9scan scanner puts the target address in its User-Agent as reversed hex."""
    return ip.encode().hex()[::-1]


def matches(needle, line, args):
    if isinstance(needle, re.Pattern):
        return needle.search(line) is not None
    return needle.replace('{ip}', args.server_ip).replace('{name}', args.server_name) in line


def select_line(needles, lines, args):
    for line in lines:
        # Skip traffic from the local network and requests to a vhost other than the public one.
        if LAN_CLIENT.match(line) or f' {args.server_name}:' not in line:
            continue
        if all(matches(needle, line, args) for needle in needles):
            return line
    return None


class Anonymizer:
    def __init__(self, args):
        self.args = args
        self.fake_clients = {}

    def fake_ip(self, ip):
        if ip == self.args.server_ip:
            return SERVER_IP_FAKE
        if ip not in self.fake_clients:
            if len(self.fake_clients) == 254:
                sys.exit('too many distinct client addresses for the fake range')
            self.fake_clients[ip] = f'{CLIENT_RANGE_FAKE}{len(self.fake_clients) + 1}'
        return self.fake_clients[ip]

    def scrub(self, text):
        text = text.replace(self.args.reverse_dns, REVERSE_DNS_FAKE).replace(self.args.server_name, SERVER_NAME_FAKE)
        return IPV4.sub(lambda match: self.fake_ip(match.group()), text)

    def scrub_user_agent(self, text):
        # Version strings look like addresses (Chrome/151.0.0.0), so only server identifiers change here.
        text = text.replace(self.args.server_ip, SERVER_IP_FAKE).replace(self.args.server_name, SERVER_NAME_FAKE)
        return text.replace(l9scan_token(self.args.server_ip), l9scan_token(SERVER_IP_FAKE))

    def anonymize(self, line):
        match = FIELDS.match(line)
        if match is None:
            sys.exit(f'selected line does not match the log format: {line}')
        client, middle, request, status, referer, separator, user_agent, rest = match.groups()
        return (self.fake_ip(client) + middle + self.scrub(request) + status + self.scrub(referer) + separator
                + self.scrub_user_agent(user_agent) + self.scrub(rest))


def unique_id_contains_ip(value, ip):
    """Checks whether a mod_unique_id value embeds the address, as it did in older Apache versions."""
    if any(char not in UNIQUE_ID_ALPHABET for char in value):
        return False
    bits = ''.join(f'{UNIQUE_ID_ALPHABET.index(char):06b}' for char in value)
    raw = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))
    return bytes(int(part) for part in ip.split('.')) in raw


def find_leaks(text, all_lines, args):
    leaks = []
    # A trailing dot is allowed so that names built from an address (<ip>.isp.example) are caught too.
    for ip in {line.split(' ', 1)[0] for line in all_lines}:
        if re.search(rf'(?<![\d.]){re.escape(ip)}(?!\d)', text):
            leaks.append(ip)
    octets = args.server_ip.split('.')
    server_forms = (
        args.server_ip,
        '-'.join(octets),
        '.'.join(reversed(octets)),
        '-'.join(reversed(octets)),
        l9scan_token(args.server_ip),
        args.server_ip.encode().hex(),
    )
    for value in (args.server_name, args.reverse_dns, *server_forms):
        if value in text:
            leaks.append(value)
    for row in text.splitlines():
        if not row or row.startswith('#'):
            continue
        match = FIELDS.match(row)
        for field in (match[1], match[3], match[5], match[8]):
            leaks += [ip for ip in IPV4.findall(field) if not ip.startswith(ALLOWED_IP_PREFIXES)]
        unique_id = UNIQUE_ID.search(row)
        if unique_id and unique_id_contains_ip(unique_id[1], args.server_ip):
            leaks.append(f'server address inside UNIQUE_ID: {unique_id[1]}')
    return leaks


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--server-ip', required=True, help="the server's public IPv4 address")
    parser.add_argument('--server-name', required=True, help='the name the server is reached by')
    parser.add_argument('--reverse-dns', required=True, help="the reverse DNS name of the server's address")
    parser.add_argument('--output', required=True)
    parser.add_argument('logs', nargs='+')
    args = parser.parse_args()

    lines = []
    for path in args.logs:
        with open(path, encoding='utf-8') as log:
            lines += log.read().splitlines()

    anonymizer = Anonymizer(args)
    out = list(HEADER)
    for label, needles in SELECT:
        line = select_line(needles, lines, args)
        if line is None:
            sys.exit(f'no line found for label {label}')
        out += [f'# {label}', anonymizer.anonymize(line), '']
    text = '\n'.join(out)

    leaks = find_leaks(text, lines, args)
    if leaks:
        sys.exit(f'not writing the fixture, identifying data would leak: {leaks}')

    with open(args.output, 'w', encoding='utf-8', newline='\n') as fixture:
        fixture.write(text)
    print(f'{len(SELECT)} lines written, {len(anonymizer.fake_clients)} client addresses replaced')


if __name__ == '__main__':
    main()
