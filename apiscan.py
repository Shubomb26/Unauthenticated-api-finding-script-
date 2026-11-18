#!/usr/bin/env python3

"""api_scan.py — unauthenticated API endpoint exposure scanner.
 
Reads a list of full endpoint URLs (domain + path, one per line) and probes

each one with six HTTP methods to determine whether data is reachable without

credentials. The result is written to an Excel workbook in the established

assessment format:
 
    FQDN | API | Method | Status Code | length | Safe / unsafe | remark | evidence
 
Features

    * WAF-aware: HTTP 2xx "Request Rejected / support ID" block pages

      (F5/iBot + Imperva signatures) are detected and classified Safe —

      a WAF block page is NOT data, so it never produces a false "Unsafe".

    * Exact per-method evidence on every row (status, error code, message,

      body snippet / WAF support ID).

    * 405 / empty-2xx responses are consolidated into the endpoint's

      meaningful row instead of getting their own rows.

    * Raw per-method results cached to JSON next to the workbook, so the

      sheet can be re-rendered (re-classified, evidence reformatted) without

      re-hitting the target.  --rescan forces a fresh run.

    * One retry pass for connection errors / timeouts.

    * HEAD is excluded by default: on this target's Envoy gateway it hangs

      ~25s with no response. Add it back with --methods if required.
 
Usage

    python3 api_scan.py endpoints.txt

    python3 api_scan.py endpoints.txt -o results.xlsx -w 16 -t 25

    python3 api_scan.py endpoints.txt --rescan

    python3 api_scan.py endpoints.txt --from-cache     # re-render sheet only
 
Input (endpoints.txt)

    One full URL per line, e.g.
https://ircmsv2.ril.com/api/CMS_NJ_Certification/1.0.0/getErrorCertificate

    Blank lines and lines starting with '#' are ignored. Duplicates removed.
 
Exit codes: 0 = completed (even with Unsafe findings), 2 = bad input.

"""

import argparse

import concurrent.futures as cf

import json

import os

import re

import sys

import time

from collections import Counter, defaultdict
 
import requests

import urllib3

from openpyxl.styles import Alignment, Font, PatternFill

from openpyxl.utils import get_column_letter

import openpyxl
 
urllib3.disable_warnings()
 
DEFAULT_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']

WRITE_METHODS = ('POST', 'PUT', 'PATCH')

# Signatures of F5/iBot + Imperva WAF block pages served with an HTTP 200.

WAF_MARKERS = (b'request rejected', b'your support id', b'access denied',

               b'access violation', b'imperva')

USER_AGENT = 'Mozilla/5.0 (Kali) API-AuthScan/1.0'
 
COLS = ['FQDN', 'API', 'Method', 'Status Code', 'length',

        'Safe / unsafe', 'remark', 'evidence']

COL_W = [20, 55, 26, 11, 9, 14, 95, 110]
 
_ILLEGAL_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
 
 
def sanitize(text):

    """Excel forbids control characters in cells - strip them."""

    if not text:

        return text

    return _ILLEGAL_RE.sub('', str(text))
 
 
# ---------------------------------------------------------------- input ------

def load_endpoints(path):

    """One full URL per line; '#' comments and blanks ignored; deduped in order."""

    seen, eps = set(), []

    with open(path) as fh:

        for n, line in enumerate(fh, 1):

            url = line.split('#', 1)[0].strip()

            if not url:

                continue

            m = re.match(r'^(https?)://[^/\s]+(/[^?\s]*)*', url)

            if not m:

                print(f'[!] line {n}: not a valid full URL, skipped: {line.strip()[:80]}',

                      file=sys.stderr)

                continue

            if url not in seen:

                seen.add(url)

                eps.append(url)

    return eps
 
 
def api_path(url):

    """(fqdn, api-path) for https://host/a/b  ->  ('host', '/a/b')."""

    m = re.search(r'//([^/]+)/?', url)

    fq = m.group(1) if m else ''

    return fq, url.split(fq, 1)[-1] if fq else url
 
 
# ---------------------------------------------------------------- probe ------

def parse_error(body):

    """Pull (code, message) from a JSON error body when present."""

    code = msg = None

    try:

        j = json.loads(body)

        if isinstance(j, dict):

            for k in ('code', 'errorCode', 'error_code', 'status'):

                if j.get(k) not in (None, ''):

                    code = j[k]

                    break

            for k in ('message', 'error', 'detail', 'Message', 'title', 'description'):

                if j.get(k) not in (None, ''):

                    msg = str(j[k])

                    break

    except Exception:

        pass

    return code, msg
 
 
def body_snippet(body, limit=400):

    """Readable evidence snippet of a response body. Binary payloads

    (images etc.) collapse to a marker instead of garbled text."""

    head = body[:limit]

    text = head.decode('utf-8', 'replace')

    if b'\x00' in head or text.count(' ') > max(3, len(head) // 50):

        return f'[binary {len(body)} bytes total]'

    return text
 
 
def probe(sess, ep, method, timeout):

    """One (endpoint, method) probe. Never raises; errors are captured."""

    try:

        if method in WRITE_METHODS:

            # Empty payload: limit blast radius if a write endpoint is open.

            r = sess.request(method, ep, data='{}',

                             headers={'Content-Type': 'application/json'},

                             allow_redirects=False, timeout=timeout)

        else:

            r = sess.request(method, ep, allow_redirects=False, timeout=timeout)

        body = r.content

        code, msg = parse_error(body)

        return dict(endpoint=ep, method=method, status=r.status_code,

                    length=len(body), location=r.headers.get('Location', ''),

                    waf=bool(r.status_code and 200 <= r.status_code < 300

                             and any(m in body[:800].lower() for m in WAF_MARKERS)),

                    code=code, message=msg,

                    body=body_snippet(body))

    except requests.exceptions.Timeout:

        return dict(endpoint=ep, method=method, status=None, length=0,

                    location='', waf=False, code=None, message=None,

                    body='timeout')

    except Exception as e:

        return dict(endpoint=ep, method=method, status=None, length=0,

                    location='', waf=False, code=None, message=None,

                    body=f'ERR {type(e).__name__}: {e}')
 
 
def scan(eps, methods, workers, timeout):

    sess = requests.Session()

    sess.verify = False

    sess.headers.update({'User-Agent': USER_AGENT})

    rows, total = [], len(eps) * len(methods)

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:

        futs = [ex.submit(probe, sess, ep, m, timeout)

                for ep in eps for m in methods]

        for i, f in enumerate(cf.as_completed(futs)):

            rows.append(f.result())

            if (i + 1) % 200 == 0:

                print(f'  .. {i + 1}/{total}', flush=True)

    return rows
 
 
def retry_errors(rows, timeout):

    """Sequential retry for rows that came back as ERR/timeout."""

    bad = [r for r in rows if r['status'] is None]

    if not bad:

        return 0

    print(f'[+] retrying {len(bad)} error/timeout rows ...', flush=True)

    sess = requests.Session()

    sess.verify = False

    sess.headers.update({'User-Agent': USER_AGENT})

    still = 0

    for i, r in enumerate(bad, 1):

        r2 = probe(sess, r['endpoint'], r['method'], timeout)

        if r2['status'] is not None:

            r.update(r2)

            print(f'    retry {i}: {r["method"]} {r["endpoint"]} -> {r2["status"]}',

                  flush=True)

        else:

            still += 1

            print(f'    retry {i}: {r["method"]} {r["endpoint"]} still failing',

                  flush=True)

        time.sleep(1)

    return still
 
 
# ---------------------------------------------------------- classification ---

def classify(api, status, length, waf):

    """(verdict, remark) for one (endpoint, status, length, waf_block)."""

    if status is None:

        return 'Safe', 'request error/timeout - no data returned; retry manually'

    if waf:

        return ('Safe', f'blocked at WAF - HTTP {status} is a block page '

                        f'(support ID), no data returned')

    if status in (401, 403):

        return 'Safe', f'auth enforced ({status}) - no data without credentials'

    if status == 405:

        return 'Safe', 'method not allowed (405) - rejected at gateway'

    if 300 <= status < 400:

        return 'Safe', f'{status} redirect (SSO/login) - no data returned unauthenticated'

    if 200 <= status < 300:

        if status == 204 or (length or 0) == 0:

            return 'Safe', f'{status} empty response - no data returned unauthenticated'

        if '/captcha' in api.lower():

            return 'Safe', ('CAPTCHA image returned unauthenticated - pre-login '

                            'endpoint, by design, non-sensitive (no PII)')

        return 'Unsafe', f'unauthenticated {status} - {length} bytes returned without credentials'

    if status == 400:

        return 'Safe', '400 payload validation - endpoint reachable, no data / no auth bypass'

    if status == 404:

        return 'Safe', '404 - endpoint not found on gateway (removed/renamed); no exposure'

    if status in (408, 410, 414, 415, 429):

        return 'Safe', f'{status} - no data returned'

    return 'Safe', f'{status} backend error unauthenticated; no data returned'
 
 
def is_noise(r):

    """405 / 204 / empty-2xx responses never get their own row."""

    if r['status'] is None:

        return False

    if r['status'] in (405, 204):

        return True

    if 200 <= r['status'] < 300 and (r['length'] or 0) == 0:

        return True

    return False
 
 
# -------------------------------------------------------------- evidence -----

def ev_text(r):

    """Exact per-method evidence: status, WAF flag, code, message, body snippet."""

    if r['status'] is None:

        return f"{r['method']}->ERR {r['body'][:200]}"

    parts = [f"{r['method']}->{r['status']}"]

    if r.get('waf'):

        parts.append('[WAF BLOCK PAGE]')

    if r.get('code') not in (None, ''):

        parts.append(f"code={r['code']}")

    if r.get('message'):

        parts.append(f"msg='{str(r['message'])[:120]}'")

    s = ' '.join(parts)

    if 200 <= r['status'] < 300 and (r['length'] or 0):

        s += f" body='{(r.get('body') or '')[:200]}'"

    return s
 
 
def evidence_for(rlist, methods):

    ordered = sorted(rlist, key=lambda r: methods.index(r['method'])

                     if r['method'] in methods else 99)

    return '; '.join(ev_text(r) for r in ordered)
 
 
def summarize_noise(rlist, methods):

    """Remark add-on listing 405 / empty methods for one endpoint."""

    parts = []

    m405 = [m for m in methods if any(r['status'] == 405 and r['method'] == m

                                      for r in rlist)]

    if m405:

        parts.append('405 method-not-allowed: ' + ', '.join(m405))

    empt = [f'{r["method"]} ({r["status"]})' for r in rlist

            if r['status'] is not None and r['status'] != 405 and is_noise(r)]

    if empt:

        parts.append('empty/no-data response: ' + ', '.join(empt))

    return (' | ' + '; '.join(parts)) if parts else ''
 
 
def consolidate(rlist, methods):

    """Raw per-method results for ONE endpoint -> output rows.
 
    Rules: significant responses (401/403/404/4xx/5xx, 2xx-with-data, WAF

    block) get a status per method; 405/empty-2xx fold into the remark of

    the endpoint's row(s). Every row carries full per-method evidence.

    """

    ep = rlist[0]['endpoint']

    fq, api = api_path(ep)

    sig = [r for r in rlist if not is_noise(r)]

    noise_note = summarize_noise(rlist, methods)

    noise_ev = '; '.join(ev_text(r) for r in rlist

                         if is_noise(r) and r['status'] is not None)
 
    def row(label, status, length, verdict, remark, ev):

        return dict(fqdn=fq, api=api, method=label,

                    status=(status if status is not None else 'ERR'),

                    length=length, verdict=verdict, remark=remark,

                    evidence=ev, url=ep)
 
    if not sig:

        rep = 405 if any(r['status'] == 405 for r in rlist) else 204

        verdict, _ = classify(api, rep, 0, False)

        return [row('ALL', rep, 0, verdict,

                    f'all tested methods: {noise_note.lstrip(" | ") or rep}',

                    evidence_for(rlist, methods))]
 
    by_key = defaultdict(list)

    for r in sig:

        by_key[(r['status'], bool(r.get('waf')))].append(r)
 
    if len(by_key) == 1:

        (st, waf) = next(iter(by_key))

        grp = by_key[(st, waf)]

        mlabel = ('ALL' if len(sig) == len(rlist)

                  else ', '.join(r['method'] for r in sorted(

                      grp, key=lambda r: methods.index(r['method']))))

        length = max((r['length'] or 0) for r in grp)

        verdict, remark = classify(api, st, length, waf)

        if len(sig) == len(rlist):

            ev = evidence_for(rlist, methods)

        else:

            ev = evidence_for(grp, methods)

            if noise_ev:

                ev += ' | noise: ' + noise_ev

            remark += noise_note

        return [row(mlabel, st, length, verdict, remark, ev)]
 
    rows_out, first = [], True

    for r in sorted(sig, key=lambda x: methods.index(x['method'])):

        verdict, remark = classify(api, r['status'], r['length'], r.get('waf', False))

        ev = ev_text(r)

        if first:

            remark += noise_note

            if noise_ev:

                ev += ' | noise: ' + noise_ev

            first = False

        rows_out.append(row(r['method'], r['status'], r['length'], verdict, remark, ev))

    return rows_out
 
 
# ---------------------------------------------------------------- workbook ----

def write_workbook(xlsx, eps, rows_out, methods, sheet):

    """New workbook: 'API List' (input URLs) + result sheet in the standard

    format (last column = evidence)."""

    wb = openpyxl.Workbook()

    src = wb.active

    src.title = 'API List'

    src.append(['Endpoint URL'])

    for ep in eps:

        src.append([ep])

    src.column_dimensions['A'].width = 80
 
    out = wb.create_sheet(sheet)

    out.append(COLS)
 
    def mkey(r):

        """Method-order sort key. Row labels are a single method, 'ALL', or a

        comma-joined list - use the first known method, else 'ALL'."""

        head = r['method'].split(',')[0].strip()

        return methods.index(head) if head in methods else 99
 
    order = {'Unsafe': 0, 'Safe': 1}

    rows_out.sort(key=lambda r: (order.get(r['verdict'], 2), r['api'], mkey(r)))

    for r in rows_out:

        out.append([sanitize(r['fqdn']), sanitize(r['api']), r['method'],

                    r['status'], r['length'], r['verdict'],

                    sanitize(r['remark']), sanitize(r['evidence'])])
 
    for i, w in enumerate(COL_W, 1):

        out.column_dimensions[get_column_letter(i)].width = w

    for c in out[1]:

        c.fill = PatternFill('solid', fgColor='305496')

        c.font = Font(color='FFFFFF', bold=True)

    wrap = Alignment(wrap_text=True, vertical='top')

    red = PatternFill('solid', fgColor='FFC7CE')

    green = PatternFill('solid', fgColor='C6EFCE')

    for row in out.iter_rows(min_row=2):

        fill = red if row[5].value == 'Unsafe' else green

        for c in row:

            c.fill = fill

            if c.column in (7, 8):

                c.alignment = wrap

    out.freeze_panes = 'A2'

    wb.save(xlsx)
 
 
# ---------------------------------------------------------------- main -------

def main():

    ap = argparse.ArgumentParser(description='Unauthenticated API exposure scanner')

    ap.add_argument('endpoints', help='text file, one full endpoint URL per line')

    ap.add_argument('-o', '--output', default='api_scan_results.xlsx',

                    help='output workbook (default: api_scan_results.xlsx)')

    ap.add_argument('--sheet', default='Result',

                    help='result sheet name (default: Result)')

    ap.add_argument('--methods', default=','.join(DEFAULT_METHODS),

                    help='comma-separated method list '

                         f'(default: {",".join(DEFAULT_METHODS)}; HEAD excluded - '

                         'it hangs ~25s on this Envoy gateway)')

    ap.add_argument('-w', '--workers', type=int, default=16)

    ap.add_argument('-t', '--timeout', type=int, default=25)

    ap.add_argument('--rescan', action='store_true',

                    help='ignore the raw cache and re-hit every endpoint')

    ap.add_argument('--from-cache', action='store_true',

                    help='skip the network entirely; re-render from the cache')

    a = ap.parse_args()
 
    methods = [m.strip().upper() for m in a.methods.split(',') if m.strip()]

    eps = load_endpoints(a.endpoints)

    if not eps:

        print('error: no valid endpoint URLs found in input', file=sys.stderr)

        sys.exit(2)
 
    stem = a.output.rsplit('.', 1)[0]

    cache, findings = f'{stem}.raw.json', f'{stem}.findings.json'
 
    if a.from_cache:

        if not os.path.exists(cache):

            print(f'error: {cache} not found for --from-cache', file=sys.stderr)

            sys.exit(2)

        rows = json.load(open(cache))

        print(f'[+] reusing cached {len(rows)} responses from {cache}')

    elif a.rescan or not os.path.exists(cache):

        print(f'[+] scanning {len(eps)} endpoints x {len(methods)} methods '

              f'({a.workers} workers, {a.timeout}s timeout) ...', flush=True)

        rows = scan(eps, methods, a.workers, a.timeout)

        still = retry_errors(rows, a.timeout)

        if still:

            print(f'[!] {still} rows still erroring - flagged ERR in the sheet')

        json.dump(rows, open(cache, 'w'))

        print(f'[+] scanned {len(rows)} responses -> {cache}')

    else:

        rows = json.load(open(cache))

        print(f'[+] {cache} exists - reusing cached {len(rows)} responses '

              f'(use --rescan to force a fresh scan)')
 
    by_ep = defaultdict(list)

    for r in rows:

        by_ep[r['endpoint']].append(r)

    rows_out = []

    for ep in eps:

        if ep in by_ep:

            rows_out.extend(consolidate(by_ep[ep], methods))
 
    unf = [r for r in rows_out if r['verdict'] == 'Unsafe']

    json.dump(unf, open(findings, 'w'), indent=2)
 
    print(f'[+] verdicts: {dict(Counter(r["verdict"] for r in rows_out))}')

    print(f'[+] WAF-block responses: '

          f'{sum(1 for r in rows if r.get("waf"))} '

          f'({len({r["endpoint"] for r in rows if r.get("waf")})} endpoints)')

    print(f'[+] errors/timeouts: {sum(1 for r in rows if r["status"] is None)}')

    print(f'[+] Unsafe findings: {len(unf)}')

    for f in unf:

        print(f'    {f["method"]:22} {f["status"]} {f["api"]}')
 
    write_workbook(a.output, eps, rows_out, methods, a.sheet)

    print(f'[+] {len(rows_out)} rows for {len(by_ep)} endpoints -> {a.output} '

          f'(sheet "{a.sheet}")')

    print(f'[+] findings -> {findings}')
 
 
if __name__ == '__main__':

    main()

 