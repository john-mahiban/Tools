
"""
PF-ADS Correlator - Prefetch Analyzer (starter)
Author: John Jeffery Mahiban
Website: https://rootkitdiaries.com

lightweight Prefetch (.pf) parser + optional correlation with ADS Hunter JSON output.
This is a starter implementation that uses a combination of available libraries (if installed)
and safe heuristics when libraries are not available. It focuses on producing useful
forensic output (exe name, run count when available, last run timestamps, and ASCII file
references extracted from the prefetch blob). Correlation with ADS Hunter output is
provided by path/hash/temporal heuristics.

"""

import argparse
import json
import os
import re
import sys
import struct
from datetime import datetime, timedelta
from pathlib import Path

# ---------- Utility helpers ----------

def filetime_to_dt(filetime):
    """Convert Windows FILETIME (100-ns since 1601-01-01) to ISO string.
    Accepts integer or bytes (little-endian 64-bit)."""
    try:
        if isinstance(filetime, bytes):
            filetime = struct.unpack('<Q', filetime)[0]
        # Windows FILETIME 0 is 1601-01-01; convert to Unix epoch
        unix_ts = (filetime - 116444736000000000) / 10000000
        return datetime.utcfromtimestamp(unix_ts).isoformat() + 'Z'
    except Exception:
        return None


def extract_ascii_strings(blob, min_len=4):
    """Return list of ASCII-like strings extracted from a bytes blob."""
    try:
        text = blob.decode('latin-1', errors='ignore')
    except Exception:
        text = ''.join(chr(b) if 32 <= b < 127 else '\x00' for b in blob)
    # find runs of printable characters
    candidates = re.findall(r'[A-Za-z0-9_\\/:. \-]{%d,}' % min_len, text)
    # de-dup while preserving order
    seen = set()
    out = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


# ---------- Prefetch parsing (best-effort) ----------

def parse_prefetch_file(path):
    """Parse a single .pf file with best-effort extraction.
    Returns a dict with keys: filename, exe_name, run_count, last_run, file_references (list), raw_size
    """
    result = {
        'source_file': str(path),
        'filename': os.path.basename(path),
        'exe_name': None,
        'run_count': None,
        'last_run_times': [],
        'file_references': [],
        'raw_size': None,
        'notes': []
    }

    p = Path(path)
    try:
        blob = p.read_bytes()
        result['raw_size'] = len(blob)
    except Exception as e:
        result['notes'].append(f'ERROR_READING: {e}')
        return result

    # Attempt 1: use an installed prefetch parsing library if available
    try:
        # Many environments do not have this; wrapped in try/except
        import prefetch  # type: ignore
        # Some libs have parse_file or PrefetchFile class; attempt a few approaches
        try:
            pf = prefetch.PrefetchFile(blob)
        except Exception:
            pf = prefetch.parse_file(str(path))

        # depending on lib, attribute names differ
        exe = getattr(pf, 'exe_name', None) or getattr(pf, 'filename', None) or None
        rc = getattr(pf, 'run_count', None) or getattr(pf, 'run_counts', None) or None
        refs = getattr(pf, 'file_references', None) or getattr(pf, 'file_access_list', None) or None
        times = getattr(pf, 'last_run', None) or getattr(pf, 'last_run_times', None) or None

        if exe:
            result['exe_name'] = exe
        if isinstance(rc, int):
            result['run_count'] = rc
        elif isinstance(rc, (list, tuple)) and rc:
            result['run_count'] = rc[0]
        if refs:
            result['file_references'] = list(refs)
        if times:
            # normalize
            if isinstance(times, (list, tuple)):
                for t in times:
                    try:
                        if isinstance(t, int):
                            result['last_run_times'].append(filetime_to_dt(t))
                        else:
                            result['last_run_times'].append(str(t))
                    except Exception:
                        result['last_run_times'].append(str(t))
            else:
                result['last_run_times'].append(str(times))

        result['notes'].append('PARSED_WITH_PREFETCH_LIB')
        return result
    except Exception:
        # library not available or failed; fall back to heuristics below
        pass

    # Heuristic extraction:
    strings = extract_ascii_strings(blob, min_len=6)

    # Heuristic 1: find first .exe-like token (full path or just file)
    exe_candidate = None
    for s in strings:
        if s.lower().endswith('.exe') or '\\' in s and s.lower().endswith('.exe'):
            exe_candidate = s.strip()
            break
    if exe_candidate:
        result['exe_name'] = exe_candidate
    else:
        # fallback: take first short string with .exe inside
        for s in strings:
            if '.exe' in s.lower():
                result['exe_name'] = s.strip()
                break

    # Heuristic 2: file references - any path-like strings
    refs = [s for s in strings if '\\' in s or '/' in s]
    # Keep top 200 references to limit size
    result['file_references'] = refs[:200]

    # Heuristic 3: attempt to find FILETIME-like 64-bit values near known windows offsets
    # Search for repeating 8-byte sequences that convert to plausible dates (post-2000)
    plausible_times = []
    for offset in range(0, min(len(blob)-8, 1024), 8):
        try:
            v = struct.unpack_from('<Q', blob, offset)[0]
            if v > 116444736000000000 and v < 1654041600000000000:
                # plausible windows FILETIME
                dt = filetime_to_dt(v)
                if dt:
                    plausible_times.append((offset, dt))
        except Exception:
            continue
    # keep unique dt strings
    seen = set()
    for off, dt in sorted(plausible_times, key=lambda x: x[0]):
        if dt not in seen:
            result['last_run_times'].append(dt)
            seen.add(dt)
            if len(result['last_run_times']) >= 5:
                break

    if not result['exe_name']:
        result['notes'].append('HEURISTIC_EXE_NOT_FOUND')
    else:
        result['notes'].append('HEURISTIC_EXE_FOUND')

    result['notes'].append('HEURISTIC_PARSE')
    return result


# ---------- ADS correlation ----------

def load_ads_hunter_json(path):
    """Load ADS Hunter JSON output. Expected format:
    [{'file_path': 'C:/path/file', 'streams': [{'name': 'stream', 'size': 123, 'sha256': '...'}], ...}]
    This function is permissive and will attempt to normalise common variants.
    """
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f'ERROR: Could not open ADS JSON: {e}', file=sys.stderr)
        return []

    normalized = []
    # Normalise a few common shapes
    if isinstance(data, dict) and 'results' in data:
        data = data['results']
    for entry in data:
        # Accept either dict with file path and streams, or simple tuples
        file_path = entry.get('file') or entry.get('file_path') or entry.get('path') or entry.get('filename')
        streams = entry.get('streams') or entry.get('ads') or entry.get('streams_found') or []
        norm_streams = []
        for s in streams:
            if isinstance(s, dict):
                name = s.get('name') or s.get('stream')
                sha = s.get('sha256') or s.get('hash')
                size = s.get('size')
                norm_streams.append({'name': name, 'sha256': sha, 'size': size})
            else:
                norm_streams.append({'name': str(s), 'sha256': None, 'size': None})
        normalized.append({'file_path': file_path, 'streams': norm_streams})
    return normalized


def correlate(prefetch_entries, ads_entries, time_delta_hours=24):
    """Correlate prefetch entries with ADS entries using several heuristics:
    - File reference match: ADS parent path appears in prefetch file_references
    - Name match: ADS stream or parent filename appears in exe_name or file_references
    - Temporal proximity: ads stream modified/created near prefetch last run times (best-effort)
    Returns a list of correlation records.
    """
    correlations = []
    for pf in prefetch_entries:
        pf_refs = [r.lower() for r in pf.get('file_references', []) if isinstance(r, str)]
        pf_exe = (pf.get('exe_name') or '').lower()
        pf_times = pf.get('last_run_times', [])

        for ads in ads_entries:
            ads_parent = (ads.get('file_path') or '').lower()
            match_types = []
            score = 0

            # File reference substring match
            if ads_parent and any(ads_parent in r for r in pf_refs):
                match_types.append('FileRef')
                score += 3

            # exe name contains parent or vice versa
            if ads_parent and (ads_parent in pf_exe or pf_exe in ads_parent):
                match_types.append('ExePath')
                score += 2

            # stream name appears in file refs
            for s in ads.get('streams', []):
                sname = (s.get('name') or '').lower()
                if sname and any(sname in r for r in pf_refs):
                    match_types.append('StreamNameRef')
                    score += 2

            # temporal heuristic: if ads contains no times we skip; otherwise check mtime/ctime fields if present
            # ADS Hunter JSON commonly doesn't include timestamps; if stream dict has 'modified' try to use it
            temporal_hit = False
            for s in ads.get('streams', []):
                for ts_field in ['modified', 'mtime', 'created', 'ctime']:
                    if s.get(ts_field):
                        try:
                            adt = datetime.fromisoformat(s.get(ts_field))
                            for pft in pf_times:
                                try:
                                    pdt = datetime.fromisoformat(pft.replace('Z', ''))
                                    if abs((adt - pdt).total_seconds()) <= time_delta_hours * 3600:
                                        temporal_hit = True
                                        break
                                except Exception:
                                    continue
                        except Exception:
                            continue
            if temporal_hit:
                match_types.append('Temporal')
                score += 1

            if match_types:
                correlations.append({
                    'prefetch_file': pf.get('source_file'),
                    'pf_exe': pf.get('exe_name'),
                    'ads_parent': ads_parent,
                    'ads_streams': ads.get('streams'),
                    'match_types': list(set(match_types)),
                    'score': score
                })
    # sort by score desc
    correlations.sort(key=lambda x: x.get('score', 0), reverse=True)
    return correlations


# ---------- CLI and runner ----------

def main():
    parser = argparse.ArgumentParser(description='PF-ADS Correlator - Prefetch + ADS correlation (starter)')
    parser.add_argument('--prefetch', '-p', required=True, help='Path to Prefetch folder (or single .pf file)')
    parser.add_argument('--ads', '-a', required=False, help='Path to ADS Hunter JSON output (optional)')
    parser.add_argument('--out', '-o', required=False, default='pf_ads_results.json', help='Output JSON file')
    parser.add_argument('--csv', required=False, help='Optional CSV output')
    parser.add_argument('--limit', type=int, default=0, help='Limit number of prefetch files to parse (0 = all)')

    args = parser.parse_args()

    pf_path = Path(args.prefetch)
    pf_files = []
    if pf_path.is_dir():
        pf_files = sorted([str(p) for p in pf_path.glob('*.pf')])
    elif pf_path.is_file() and pf_path.suffix.lower() == '.pf':
        pf_files = [str(pf_path)]
    else:
        print('ERROR: --prefetch must point to a Prefetch directory or a .pf file', file=sys.stderr)
        sys.exit(2)

    if args.limit and args.limit > 0:
        pf_files = pf_files[:args.limit]

    print(f'Parsing {len(pf_files)} prefetch files...')
    parsed = []
    for f in pf_files:
        try:
            p = parse_prefetch_file(f)
            parsed.append(p)
        except Exception as e:
            print(f'Error parsing {f}: {e}', file=sys.stderr)

    ads_entries = []
    if args.ads:
        ads_entries = load_ads_hunter_json(args.ads)
        print(f'Loaded {len(ads_entries)} ADS Hunter entries')

    correlations = []
    if ads_entries:
        correlations = correlate(parsed, ads_entries)
        print(f'Found {len(correlations)} correlations (heuristic)')

    out = {
        'author': 'John Jeffery Mahiban',
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'prefetch_count': len(parsed),
        'parsed': parsed,
        'ads_count': len(ads_entries),
        'correlations': correlations
    }

    with open(args.out, 'w', encoding='utf-8') as fh:
        json.dump(out, fh, indent=2)
    print(f'Wrote JSON output to {args.out}')

    if args.csv:
        import csv
        csvf = args.csv
        # write simple correlations CSV
        with open(csvf, 'w', newline='', encoding='utf-8') as cf:
            writer = csv.writer(cf)
            writer.writerow(['prefetch_file', 'pf_exe', 'ads_parent', 'match_types', 'score'])
            for c in correlations:
                writer.writerow([c.get('prefetch_file'), c.get('pf_exe'), c.get('ads_parent'), ';'.join(c.get('match_types', [])), c.get('score')])
        print(f'Wrote CSV correlations to {csvf}')


if __name__ == '__main__':
    main()
