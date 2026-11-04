#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent checks of actual app JSON export against fixture-owned oracles."""
import json
import sys
from pathlib import Path

checks = 0

def check(value, message):
    global checks
    checks += 1
    if not value:
        raise AssertionError(message)

def load(path):
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    check(rows[0]['type'] == 'capture' and rows[0]['platform'] == 'FreeBSD-amd64', f'{path}: identity')
    return rows[0]['metadata'], rows[1:]

def signed32(raw):
    return (raw + 2**31) % 2**32 - 2**31

root = Path(sys.argv[1])
for profile in ('all', 'core', 'read', 'write', 'openat', 'exit7', 'cancel', 'term', 'fault', 'killed', 'exec_native', 'exec_compat'):
    meta, events = load(root / f'{profile}.jsonl')
    ready = (root / f'{profile}.fixture').read_text().splitlines()[0].split('\t')
    pid, tid, uid, gid = map(int, ready[1:])
    check(all(e['pid'] == pid and e['uid'] == uid and e['gid'] == gid for e in events), f'{profile}: scope/credentials')
    origin = int(meta['raw_origin_ns'])
    for event in events:
        check(event['timestamp_ns'] == event['raw_start_ns'] - origin and event['timestamp_ns'] >= 0, f'{profile}: clock')
        check(len(event['stack']) == len(event['symbols']), f'{profile}: symbol/frame association')
        check(event['state'] != 'completed' or (event['entry_present'] and event['return_present'] and event['errno_bits'] is not None), f'{profile}: state evidence')
    if profile in ('cancel', 'term'):
        check(meta['stop_reason'] == 'cancelled' and meta['complete'] == 'false', f'{profile}: cancellation metadata')
        check(any(e['state'] == 'cancelled' and e['syscall'] == 'read' and e['result'] is None for e in events), f'{profile}: interrupted read')
        check(meta['missing_snapshots'] == '0' and meta['runtime_errors'] == '0', f'{profile}: no invented output snapshot')
    elif profile == 'fault':
        check(meta['complete'] == 'false' and int(meta['runtime_errors']) > 0 and int(meta['missing_snapshots']) > 0, 'copy fault surfaced')
        check(any(e['syscall'] == 'openat' and e['result'] == -1 and e['errno_bits'] == 14 and e['entry_present'] and e['return_present'] for e in events), 'EFAULT result retained')
    elif profile.startswith('exec_'):
        check(meta['complete'] == 'false' and meta['stop_reason'] == 'target-change' and 'executed' in meta['diagnostic'], f'{profile}: identity boundary')
    else:
        check(meta['complete'] == 'true' and meta['stop_reason'] == 'target-exit', f'{profile}: completeness')
        check(all(meta[key] == '0' for key in ('runtime_errors', 'drops', 'unresolved', 'missing_snapshots')), f'{profile}: quality counters')
    if profile in ('all', 'core', 'read', 'write', 'openat', 'exit7'):
        allowed = {'openat','read','write'} if profile != 'all' else None
        if profile in ('read','write','openat'): allowed = {profile}
        check(allowed is None or all(e['syscall'] in allowed for e in events), f'{profile}: event filter')
        for line in (root / f'{profile}.fixture').read_text().splitlines():
            if not line.startswith('EXPECT\t'): continue
            _, p, t, call, index, fd, third, result, error, path = line.split('\t')
            if allowed and call not in allowed: continue
            matches = [e for e in events if e['syscall'] == call and e['tid'] == int(t) and e['state'] == 'completed'
                       and signed32(e['arguments'][0]['raw']) == int(fd) and e['arguments'][2]['raw'] == int(third)
                       and e['result'] == int(result) and e['errno_bits'] == int(error)]
            if call == 'openat': matches = [e for e in matches if e['arguments'][1]['text'] == path]
            check(len(matches) == 1, f'{profile}: unique oracle {index}')
            event = matches[0]
            if call == 'write': check(event['arguments'][1]['text'] == ('native64' if int(third) == 8 else 'n'), f'{profile}: entry buffer')
            if call == 'read': check(event['arguments'][1]['text'] == ('native64' if int(result) == 8 else ''), f'{profile}: return buffer')
            check(any('!main+' in symbol for symbol in event['symbols']), f'{profile}: captured main symbol')
    if profile == 'all':
        check(int(meta['syscall_count']) > 500 and any(e['syscall'] == '_exit' and e['state'] == 'entry-only' for e in events), 'full catalog/exit')
    if profile == 'exit7': check(meta[f'target_{pid}_exit_status'] == str(7 << 8), 'target nonzero wait status')
    if profile == 'killed': check(meta[f'target_{pid}_exit_status'] == '15', 'target signal status')

meta, events = load(root / 'advanced/all.jsonl')
check(meta['complete'] == 'true' and all(meta[k] == '0' for k in ('runtime_errors','drops','unresolved','missing_snapshots')), 'advanced quality')
oracle = [line.split('\t') for line in (root / 'advanced/all.fixture').read_text().splitlines()]
pid = int(oracle[0][1])
check(all(e['pid'] == pid for e in events), 'advanced PID filter excludes child')
for row in oracle:
    if row[0] == 'THREAD':
        tid, index, fd, count, failed = map(int,row[1:]); payload = bytes((84,index,0,255,34,92,10,127)).decode('latin1')
        matches = [e for e in events if e['syscall'] == 'write' and e['tid'] == tid and e['arguments'][0]['raw'] == fd and e['arguments'][1]['text'] == payload]
        check(len(matches) == count == 20 and not failed and all(e['result'] == 8 and e['errno_bits'] == 0 for e in matches), f'thread {index}: all binary buffers/correlation')
    elif row[0] == 'NETWORK':
        client, peer, sent, se, received, re = map(int,row[1:]); payload = bytes((78,0,255,34,92,10,127,90)).decode('latin1')
        check(any(e['syscall'] == 'sendto' and e['arguments'][0]['raw'] == client and e['arguments'][1]['text'] == payload and e['result'] == sent == 8 and e['errno_bits'] == se == 0 for e in events), 'sendto binary snapshot')
        check(any(e['syscall'] == 'read' and e['arguments'][0]['raw'] == peer and e['arguments'][1]['text'] == payload and e['result'] == received == 8 and e['errno_bits'] == re == 0 for e in events), 'socket read binary snapshot')
    elif row[0] == 'SENDFILE':
        client, offset, count, pointer, result, error = map(int,row[1:])
        matches = [e for e in events if e['syscall'] == 'sendfile']
        check(len(matches) == 1, 'sendfile unique')
        event = matches[0]; args = [a['raw'] for a in event['arguments']]
        check(len(args) == 7 and signed32(args[0]) == -1 and args[1:] == [client,offset,count,0,pointer,0x40], 'all seven exact argument lanes')
        check(event['result'] == result == -1 and event['errno_bits'] == error == 9, 'sendfile EBADF')
    elif row[0] == 'PROCESS':
        child, status = map(int,row[1:])
        check(any(e['syscall'] == 'fork' and e['result'] == child for e in events), 'parent fork return')
        check(any(e['syscall'] == 'wait4' and e['result'] == child for e in events) and status == 7 << 8, 'parent wait return')
check(any(e['syscall'] == 'mmap' and e['result'] > 0 and e['errno_bits'] == 0 for e in events), '64-bit mapping result')
for profile in ('limit','byte-limit'):
    meta, events = load(root / f'{profile}.jsonl')
    check(meta['complete'] == 'false' and meta['status'] == 'failed' and 'budget' in meta['diagnostic'], f'{profile}: explicit bounded failure')
meta, events = load(root / 'no-extras.jsonl')
check(meta['complete'] == 'true' and all(meta[k] == 'false' for k in ('strings','buffers','stacks')), 'optional capture flags')
check(events and all(not e['stack'] and not e['symbols'] and all(a['text'] is None for a in e['arguments']) for e in events), 'disabled snapshots and stacks')
check(len(list((root / 'ui').glob('*.db'))) == 3, 'three independent UI export files')
first_snapshot = next(p for p in (root / 'ui').glob('*.db.jsonl') if p.name.count('.db') == 1)
active_meta, active_events = load(first_snapshot)
check(active_meta['status'] == 'capturing' and active_meta['complete'] == 'false', 'in-progress UI snapshot explicitly incomplete')
meta, events = load(root / 'ui/live.jsonl')
check(meta['pauses'] == '1' and meta['complete'] == 'false' and meta['stop_reason'] == 'target-exit', 'UI pause/resume gap preserved')
_, filtered = load(root / 'replay-read.jsonl')
check(filtered and all(e['syscall'] == 'read' for e in filtered), 'replay event filter')
for profile in ('replay','small','resize','interrupt','live'):
    check((root / f'ui/{profile}.pty').stat().st_size > 0, f'{profile}: PTY evidence')
results = (root / 'results.log').read_text()
check(results.count('RESULT\t') == 20 and results.count('PASS: PTY') == 5, 'all supervisors passed')
print(f'PASS: {checks} independent application checks (fixture oracles, quality, clocks, filters, seven arguments, binary buffers, threads, network, process and UI exports)')

# These controls mutate real completed evidence and require this independent
# verifier to reject each change. No fixture values are taken from the backend.
if len(sys.argv) > 2 and sys.argv[2] == '--negative':
    import shutil
    import subprocess
    import tempfile
    mutations = ('pid','clock','result','errno','seventh','binary','quality','symbols','active')
    for mutation in mutations:
        with tempfile.TemporaryDirectory(prefix='procmon-app-mutant-') as temporary:
            altered = Path(temporary) / 'evidence'
            shutil.copytree(root,altered)
            file = altered / ('advanced/all.jsonl' if mutation in ('seventh','binary') else
                              'limit.jsonl' if mutation == 'quality' else
                              str(first_snapshot.relative_to(root)) if mutation == 'active' else 'all.jsonl')
            rows = [json.loads(line) for line in file.read_text().splitlines()]
            if mutation == 'pid': rows[1]['pid'] += 1
            elif mutation == 'clock': rows[1]['timestamp_ns'] += 1
            elif mutation in ('result','errno'):
                event = next(e for e in rows[1:] if e['syscall'] == 'openat' and e['result'] > 0)
                event['result' if mutation == 'result' else 'errno_bits'] += 1
            elif mutation == 'seventh': next(e for e in rows[1:] if e['syscall'] == 'sendfile')['arguments'][6]['raw'] ^= 1
            elif mutation == 'binary':
                event = next(e for e in rows[1:] if e['syscall'] == 'write' and e['arguments'][1]['text'] and e['arguments'][1]['text'].startswith('T\x00'))
                event['arguments'][1]['text'] = 'corrupt'
            elif mutation in ('quality','active'): rows[0]['metadata']['complete'] = 'true'
            elif mutation == 'symbols':
                for event in rows[1:]: event['symbols'] = ['[unavailable]'] * len(event['stack'])
            file.write_text(''.join(json.dumps(row,ensure_ascii=True) + '\n' for row in rows))
            result = subprocess.run([sys.executable,__file__,str(altered)],capture_output=True,text=True)
            check(result.returncode != 0,f'negative control accepted: {mutation}')
    print(f'REJECTED: {len(mutations)} independent application corruption controls')
