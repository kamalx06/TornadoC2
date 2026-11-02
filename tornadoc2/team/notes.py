class NotesStore:
    """Per-beacon notes under <base>/bnotes/<bid>.json, plus a
    single engagement-wide list at <base>/notes.json."""

    MAX_NOTES_PER_BEACON = 10000
    MAX_NOTES_GLOBAL     = 10000

    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.per_dir = os.path.join(base_dir, 'bnotes')
        self.global_path = os.path.join(base_dir, 'notes.json')
        self._lock = threading.Lock()
        os.makedirs(self.per_dir, exist_ok=True)
        try:
            os.chmod(self.per_dir, 0o700)
        except OSError:
            pass

    def _per_path(self, bid: int) -> str:
        return os.path.join(self.per_dir, f'{int(bid)}.json')

    def add_beacon(self, bid: int, author: str, text: str) -> dict:
        entry = {'ts': time.time(), 'author': author,
                 'text': text}
        with self._lock:
            lst = self._load_list(self._per_path(bid))
            if len(lst) >= self.MAX_NOTES_PER_BEACON:
                raise ValueError(
                    f'beacon #{bid} already has {len(lst)} '
                    f'notes; the cap is '
                    f'{self.MAX_NOTES_PER_BEACON}. Clear old '
                    f'notes first.')
            lst.append(entry)
            self._save_list(self._per_path(bid), lst)
        return entry

    def list_beacon(self, bid: int) -> list:
        with self._lock:
            return self._load_list(self._per_path(bid))

    def clear_beacon(self, bid: int) -> int:
        with self._lock:
            lst = self._load_list(self._per_path(bid))
            n = len(lst)
            self._save_list(self._per_path(bid), [])
        return n

    def add_global(self, author: str, text: str,
                   tags: list) -> dict:
        entry = {'ts': time.time(), 'author': author,
                 'text': text, 'tags': list(tags or [])}
        with self._lock:
            lst = self._load_list(self.global_path)
            if len(lst) >= self.MAX_NOTES_GLOBAL:
                raise ValueError(
                    f'engagement notes already has {len(lst)} '
                    f'entries; the cap is '
                    f'{self.MAX_NOTES_GLOBAL}. Clear or archive '
                    f'old notes first.')
            lst.append(entry)
            self._save_list(self.global_path, lst)
        return entry

    def list_global(self) -> list:
        with self._lock:
            return self._load_list(self.global_path)

    def search_global(self, term: str) -> list:
        t = term.lower()
        with self._lock:
            return [e for e in self._load_list(self.global_path)
                    if t in (e.get('text') or '').lower()
                    or any(t in tag.lower()
                           for tag in e.get('tags', []))]

    def _load_list(self, path: str) -> list:
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                d = json.load(fh)
            if not isinstance(d, list):
                raise ValueError(
                    f'expected list, got {type(d).__name__}')
            return d
        except FileNotFoundError:
            return []
        except (OSError, ValueError) as exc:
            import sys as _sys
            print(f"[NOTES] {path} is corrupt: "
                  f"{type(exc).__name__}: {exc}; renaming to "
                  f".corrupt and starting fresh",
                  file=_sys.stderr, flush=True)
            try:
                backup = path + '.corrupt'
                if not os.path.isfile(backup):
                    os.rename(path, backup)
            except OSError:
                pass
            return []

    def _save_list(self, path: str, lst: list) -> None:
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(lst, fh, indent=2)
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass