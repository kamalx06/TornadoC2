#!/usr/bin/env python3
"""Report plaintext state files that at-rest encryption has not sealed.

Read-only. Run from the repository root while the server is stopped.
Exit code 1 means at least one sensitive file is still plaintext.
"""
import os
import sys

MAGIC = b'T2ENC1\n'
ROOTS = ('logs',)
NAMES = ('listeners.json',)


def main():
    bad = []
    for root in ROOTS:
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                p = os.path.join(dirpath, name)
                if name.endswith(('.txt', '.log', '.key', '.corrupt',
                                  '.tmp', '.sha256')) or name in (
                        'checkpoint.json', 'anchor.json'):
                    continue
                try:
                    if os.path.getsize(p) == 0:
                        continue
                    with open(p, 'rb') as fh:
                        head = fh.read(len(MAGIC))
                except OSError:
                    continue
                if head != MAGIC:
                    bad.append(p)
    for name in NAMES:
        if os.path.isfile(name):
            with open(name, 'rb') as fh:
                if fh.read(len(MAGIC)) != MAGIC:
                    bad.append(name)
    for p in bad:
        print('plaintext', p)
    print(f'{len(bad)} plaintext file(s)')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
