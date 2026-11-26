#!/usr/bin/env python3
# real addresses and names come only from arguments, never write them here
import argparse
import json
import re
import sys

SERVER_IP_FAKE = '192.0.2.1'
SERVER_NAME_FAKE = 'server.example.org'
CLIENT_RANGE_FAKE = '198.51.100.'
ALLOWED_IP_PREFIXES = ('192.0.2.', CLIENT_RANGE_FAKE)

HEADER = [
    '# Real modsec_audit.log entries (Serial, JSON), anonymized: client and server addresses use RFC 5737',
    '# ranges, the server name uses example.org. Everything else is byte for byte as ModSecurity logged it.',
    '# Each entry is preceded by its label, used by the tests to refer to it.',
    '',
]


def request_line(entry):
    return entry.get('request', {}).get('request_line')


def header(entry, name):
    headers = entry.get('request', {}).get('headers', {})
    return next((value for key, value in headers.items() if key.lower() == name.lower()), None)


SELECT = [
    ('get-root-browser', lambda e: request_line(e) == 'GET / HTTP/1.1' and 'Firefox' in (header(e, 'User-Agent') or '')),
    ('get-favicon-referer', lambda e: request_line(e) == 'GET /favicon.ico HTTP/1.1' and header(e, 'Referer')),
    ('post-urlencoded-curl', lambda e: request_line(e).startswith('POST ') and e['request'].get('body')),
]

IPV4 = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\d)')
UNIQUE_ID_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@-'


def dump(entry):
    return json.dumps(entry, ensure_ascii=False, separators=(',', ':'))


class Anonymizer:
    def __init__(self, args):
        self.args = args
        self.fake_clients = {}

    def fake_ip(self, ip):
        if ip in self.args.server_ip:
            return SERVER_IP_FAKE
        if ip not in self.fake_clients:
            if len(self.fake_clients) == 254:
                sys.exit('too many distinct client addresses for the fake range')
            self.fake_clients[ip] = f'{CLIENT_RANGE_FAKE}{len(self.fake_clients) + 1}'
        return self.fake_clients[ip]

    def scrub(self, text, key):
        text = text.replace(self.args.server_name, SERVER_NAME_FAKE)
        if key == 'User-Agent':
            # version strings look like addresses (chrome/151.0.0.0)
            for ip in self.args.server_ip:
                text = text.replace(ip, SERVER_IP_FAKE)
            return text
        return IPV4.sub(lambda match: self.fake_ip(match.group()), text)

    def anonymize(self, value, key=None):
        if isinstance(value, dict):
            return {k: self.anonymize(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [self.anonymize(v, key) for v in value]
        if isinstance(value, str):
            return self.scrub(value, key)
        return value


def strings_outside_user_agent(value, key=None):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from strings_outside_user_agent(v, k)
    elif isinstance(value, list):
        for v in value:
            yield from strings_outside_user_agent(v, key)
    elif isinstance(value, str) and key != 'User-Agent':
        yield value


def unique_id_contains_ip(value, ip):
    if any(char not in UNIQUE_ID_ALPHABET for char in value):
        return False
    bits = ''.join(f'{UNIQUE_ID_ALPHABET.index(char):06b}' for char in value)
    raw = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))
    return bytes(int(part) for part in ip.split('.')) in raw


def find_leaks(text, entries, args):
    leaks = []
    for ip in {entry['transaction']['remote_address'] for entry in entries}:
        if re.search(rf'(?<![\d.]){re.escape(ip)}(?!\d)', text):
            leaks.append(ip)
    for ip in args.server_ip:
        octets = ip.split('.')
        for form in (ip, '-'.join(octets), '.'.join(reversed(octets)), '-'.join(reversed(octets)), ip.encode().hex()):
            if form in text:
                leaks.append(form)
    for value in (args.server_name, args.server_name.split('.')[0]):
        if value.lower() in text.lower():
            leaks.append(value)
    for row in text.splitlines():
        if not row or row.startswith('#'):
            continue
        entry = json.loads(row)
        for value in strings_outside_user_agent(entry):
            leaks += [ip for ip in IPV4.findall(value) if not ip.startswith(ALLOWED_IP_PREFIXES)]
        transaction_id = entry['transaction']['transaction_id']
        leaks += [f'address inside transaction_id: {transaction_id}'
                  for ip in args.server_ip if unique_id_contains_ip(transaction_id, ip)]
    return leaks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server-ip', required=True, action='append', help="the server's IPv4 address")
    parser.add_argument('--server-name', required=True, help='the name the server is reached by')
    parser.add_argument('--output', required=True)
    parser.add_argument('logs', nargs='+')
    args = parser.parse_args()

    lines = []
    for path in args.logs:
        with open(path, encoding='utf-8') as log:
            lines += [line for line in log.read().splitlines() if line]
    entries = [json.loads(line) for line in lines]

    anonymizer = Anonymizer(args)
    out = list(HEADER)
    for label, predicate in SELECT:
        found = next(((line, entry) for line, entry in zip(lines, entries) if predicate(entry)), None)
        if found is None:
            sys.exit(f'no entry found for label {label}')
        line, entry = found
        if dump(entry) != line:
            sys.exit(f'entry for {label} would not stay byte for byte after re-serializing (duplicate keys?)')
        out += [f'# {label}', dump(anonymizer.anonymize(entry)), '']
    text = '\n'.join(out)

    leaks = find_leaks(text, entries, args)
    if leaks:
        sys.exit(f'not writing the fixture, identifying data would leak: {leaks}')

    with open(args.output, 'w', encoding='utf-8', newline='\n') as fixture:
        fixture.write(text)
    print(f'{len(SELECT)} entries written, {len(anonymizer.fake_clients)} client addresses replaced')


if __name__ == '__main__':
    main()
