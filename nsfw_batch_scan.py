from __future__ import annotations

import os
import posixpath
import tempfile
import threading
import time
import uuid
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
from typing import Any, Callable

import requests
from requests.adapters import HTTPAdapter

import file_ops


def _utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _normalize_remote_path(remote_path: str) -> str:
    remote_path = (remote_path or "").strip() or "/"
    if not remote_path.startswith("/"):
        remote_path = "/" + remote_path
    return remote_path


def _join_remote_path(parent: str, href: str) -> str:
    parent = _normalize_remote_path(parent)
    href = (href or "").strip()
    if not href:
        return parent
    if href.startswith("/"):
        return href
    if parent == "/":
        return "/" + href.lstrip("/")
    if parent.endswith("/"):
        return parent + href.lstrip("/")
    return parent + "/" + href.lstrip("/")


def _remote_dir_and_name(remote_path: str) -> tuple[str, str]:
    remote_path = _normalize_remote_path(remote_path)
    cleaned = remote_path.rstrip("/") or "/"
    filename = posixpath.basename(cleaned) or cleaned
    dir_path = posixpath.dirname(cleaned) or "/"
    if not dir_path.startswith("/"):
        dir_path = "/" + dir_path
    return dir_path, filename


def _get_ext(filename: str) -> str:
    filename = (filename or "").strip().lower()
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1]


def _should_score_filename(*, filename: str, include_images: bool, include_videos: bool) -> bool:
    ext = _get_ext(filename)
    if not ext:
        return False

    try:
        import nsfw_scan  # noqa: WPS433
    except Exception:
        return False

    if include_images and (ext in nsfw_scan.IMAGE_EXTS or ext in nsfw_scan.HEIF_EXTS):
        return True
    if include_videos and ext in nsfw_scan.VIDEO_EXTS:
        return True
    return False


def _create_session(pool_size: int) -> requests.Session:
    session = requests.Session()
    adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=0)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def _download_remote_to_temp(
    *,
    session: requests.Session,
    base_url: str,
    remote_path: str,
    suffix: str,
    max_bytes: int,
) -> tuple[str | None, str | None]:
    url = file_ops._build_target_url(base_url, remote_path)
    fd, tmp_path = tempfile.mkstemp(prefix="fnos_nsfw_", suffix=suffix)
    os.close(fd)

    total = 0
    try:
        with session.get(
            url,
            verify=False,
            timeout=(10, 600),
            stream=True,
            headers={"Accept-Encoding": "identity"},
        ) as resp:
            resp.raise_for_status()
            with open(tmp_path, "wb") as out:
                for chunk in resp.iter_content(chunk_size=1024 * 1024):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if max_bytes > 0 and total > max_bytes:
                        try:
                            os.remove(tmp_path)
                        except Exception:
                            pass
                        return None, "too_large"
                    out.write(chunk)
    except Exception as e:
        try:
            os.remove(tmp_path)
        except Exception:
            pass
        return None, str(e)

    return tmp_path, None


@dataclass
class BatchScanConfig:
    threshold: float = 0.7
    dedup_ip: bool = True
    include_images: bool = True
    include_videos: bool = True
    roots: list[str] | None = None
    max_targets: int = 0
    max_depth: int = 20
    max_dirs_per_target: int = 5000
    max_files_per_target: int = 50000
    max_bytes_image: int = 25 * 1024 * 1024
    max_bytes_video: int = 1024 * 1024 * 1024
    session_pool_size: int = 8
    target_workers: int = 0
    score_workers: int = 0


@dataclass
class BatchScanStatus:
    job_id: str | None = None
    running: bool = False
    cancelled: bool = False
    started_at: str | None = None
    finished_at: str | None = None
    message: str = ""
    targets_total: int = 0
    targets_done: int = 0
    dirs_scanned: int = 0
    files_seen: int = 0
    files_scored: int = 0
    flagged: int = 0
    skipped: int = 0
    errors: int = 0
    current_target_id: int | None = None


class NsfwBatchScanner:
    def __init__(
        self,
        *,
        get_targets_fn: Callable[[str, bool], list[Any]] | None = None,
        get_existing_fn: Callable[[int, str], Any] | None = None,
        upsert_fn: Callable[..., Any] | None = None,
    ):
        if get_targets_fn is None:
            from database import get_targets_by_status  # noqa: WPS433

            get_targets_fn = get_targets_by_status
        if get_existing_fn is None:
            from database import get_nsfw_scan_result  # noqa: WPS433

            get_existing_fn = get_nsfw_scan_result
        if upsert_fn is None:
            from database import upsert_nsfw_scan_result  # noqa: WPS433

            upsert_fn = upsert_nsfw_scan_result

        self._get_targets_fn = get_targets_fn
        self._get_existing_fn = get_existing_fn
        self._upsert_fn = upsert_fn

        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._thread: threading.Thread | None = None
        self._status = BatchScanStatus()
        self._score_sem: threading.BoundedSemaphore | None = None

    def start(self, config: BatchScanConfig) -> BatchScanStatus:
        should_start = False
        with self._lock:
            if self._thread and self._thread.is_alive():
                self._status.message = "Scan already running."
            else:
                self._cancel.clear()
                self._status = BatchScanStatus(
                    job_id=str(uuid.uuid4()),
                    running=True,
                    cancelled=False,
                    started_at=_utc_now_iso(),
                    message="Starting scan...",
                )
                self._thread = threading.Thread(target=self._run, args=(config,), daemon=True)
                should_start = True

        if should_start and self._thread:
            self._thread.start()
        return self._copy_status()

    def stop(self) -> BatchScanStatus:
        self._cancel.set()
        with self._lock:
            if self._status.running:
                self._status.cancelled = True
                self._status.message = "Cancelling..."
        return self._copy_status()

    def status(self) -> BatchScanStatus:
        return self._copy_status()

    def _copy_status(self) -> BatchScanStatus:
        with self._lock:
            return BatchScanStatus(**asdict(self._status))

    def _set_message(self, msg: str):
        with self._lock:
            self._status.message = msg

    def _inc(self, field: str, amount: int = 1):
        with self._lock:
            setattr(self._status, field, int(getattr(self._status, field)) + int(amount))

    def _discover_webdav_roots(self, *, base_url: str, session: requests.Session) -> list[str]:
        data = file_ops.get_remote_content(base_url, "/share/home", session=session)
        if data.get("type") != "directory":
            return ["/share/home"]

        roots: list[str] = []
        for item in data.get("items") or []:
            if not item.get("is_dir"):
                continue
            name = (item.get("name") or "").rstrip("/")
            if not name.isdigit():
                continue
            roots.append(f"/share/home/{name}/webdav")

        return roots or ["/share/home"]

    def _auto_workers(self, config: BatchScanConfig) -> tuple[int, int]:
        cpu = os.cpu_count() or 8

        t_workers = int(getattr(config, "target_workers", 0) or 0)
        if t_workers <= 0:
            t_workers = max(8, min(64, cpu * 2))
        t_workers = max(1, min(t_workers, 256))

        s_workers = int(getattr(config, "score_workers", 0) or 0)
        if s_workers <= 0:
            s_workers = max(2, min(8, cpu))
        s_workers = max(1, min(s_workers, 64))

        return t_workers, s_workers

    def _prewarm_model(self):
        try:
            import nsfw_scan  # noqa: WPS433
            from PIL import Image  # noqa: WPS433

            with tempfile.TemporaryDirectory(prefix="fnos_nsfw_warm_") as tmp_dir:
                img_path = os.path.join(tmp_dir, "warm.png")
                Image.new("RGB", (32, 32), (0, 0, 0)).save(img_path, format="PNG")
                nsfw_scan.score_image(img_path)
        except Exception:
            pass

    def _run(self, config: BatchScanConfig):
        try:
            target_workers, score_workers = self._auto_workers(config)
            self._score_sem = threading.BoundedSemaphore(value=int(score_workers))

            self._set_message(f"Preparing model... (targets={target_workers}, score={score_workers})")
            self._prewarm_model()

            rows = self._get_targets_fn("Vulnerable", bool(config.dedup_ip))
            if config.max_targets and int(config.max_targets) > 0:
                rows = list(rows)[: int(config.max_targets)]
            else:
                rows = list(rows)

            with self._lock:
                self._status.targets_total = len(rows)
                self._status.message = f"Scanning {len(rows)} vulnerable targets... (workers={target_workers})"

            max_inflight = max(8, target_workers * 3)
            with ThreadPoolExecutor(max_workers=target_workers) as executor:
                futures: set[Any] = set()

                def drain_done():
                    if not futures:
                        return
                    done, pending = wait(futures, return_when=FIRST_COMPLETED)
                    futures.clear()
                    futures.update(pending)
                    for fut in done:
                        try:
                            fut.result()
                        except Exception:
                            self._inc("errors", 1)

                for r in rows:
                    if self._cancel.is_set():
                        break
                    try:
                        target_id = int(r["id"])  # sqlite Row
                        base_url = str(r["base_url"])
                    except Exception:
                        continue

                    with self._lock:
                        self._status.current_target_id = target_id

                    futures.add(
                        executor.submit(
                            self._scan_one_target,
                            target_id=target_id,
                            base_url=base_url,
                            config=config,
                        )
                    )
                    if len(futures) >= max_inflight:
                        drain_done()

                while futures:
                    drain_done()

        except Exception as e:
            self._set_message(f"Scan failed: {e}")
        finally:
            with self._lock:
                self._status.running = False
                self._status.finished_at = _utc_now_iso()
                if self._cancel.is_set():
                    self._status.cancelled = True
                    self._status.message = self._status.message or "Cancelled."
                else:
                    self._status.message = self._status.message or "Done."

            self._score_sem = None

    def _scan_one_target(self, *, target_id: int, base_url: str, config: BatchScanConfig):
        if self._cancel.is_set():
            self._inc("targets_done", 1)
            return

        session = _create_session(max(2, int(config.session_pool_size or 8)))
        try:
            roots = (
                [str(p) for p in (config.roots or []) if str(p).strip()]
                if config.roots is not None
                else self._discover_webdav_roots(base_url=base_url, session=session)
            )
            roots = [_normalize_remote_path(p) for p in roots]

            self._scan_target(
                target_id=target_id,
                base_url=base_url,
                roots=roots,
                session=session,
                config=config,
            )
        finally:
            try:
                session.close()
            except Exception:
                pass
            self._inc("targets_done", 1)

    def _scan_target(
        self,
        *,
        target_id: int,
        base_url: str,
        roots: list[str],
        session: requests.Session,
        config: BatchScanConfig,
    ):
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque()
        for root in roots:
            queue.append((root.rstrip("/") or "/", 0))

        dirs_scanned = 0
        files_seen = 0

        while queue and not self._cancel.is_set():
            if config.max_dirs_per_target and dirs_scanned >= int(config.max_dirs_per_target):
                break
            if config.max_files_per_target and files_seen >= int(config.max_files_per_target):
                break

            current_path, depth = queue.popleft()
            current_path = _normalize_remote_path(current_path).rstrip("/") or "/"
            if current_path in visited:
                continue
            visited.add(current_path)

            data = file_ops.get_remote_content(base_url, current_path, session=session)
            if data.get("type") != "directory":
                continue

            dirs_scanned += 1
            self._inc("dirs_scanned", 1)

            for item in data.get("items") or []:
                if self._cancel.is_set():
                    break

                href = (item.get("href") or item.get("name") or "").strip()
                name = (item.get("name") or "").strip()
                if not href or not name:
                    continue

                is_dir = bool(item.get("is_dir"))
                if is_dir:
                    if depth >= int(config.max_depth or 0):
                        continue
                    child = _join_remote_path(current_path, href)
                    queue.append((child, depth + 1))
                    continue

                cleaned_name = name.rstrip("/")
                if not _should_score_filename(
                    filename=cleaned_name,
                    include_images=bool(config.include_images),
                    include_videos=bool(config.include_videos),
                ):
                    continue

                remote_child = _join_remote_path(current_path, href)
                files_seen += 1
                self._inc("files_seen", 1)

                self._score_one(
                    target_id=target_id,
                    base_url=base_url,
                    remote_path=remote_child,
                    filename=cleaned_name,
                    session=session,
                    config=config,
                )

                if config.max_files_per_target and files_seen >= int(config.max_files_per_target):
                    break

    def _score_one(
        self,
        *,
        target_id: int,
        base_url: str,
        remote_path: str,
        filename: str,
        session: requests.Session,
        config: BatchScanConfig,
    ):
        remote_path = _normalize_remote_path(remote_path)
        existing = self._get_existing_fn(target_id, remote_path)
        if existing is not None:
            try:
                if existing["decision"] in {"nsfw", "clean", "unsupported", "skipped"}:
                    return
            except Exception:
                pass

        suffix = ""
        if "." in filename:
            suffix = "." + filename.rsplit(".", 1)[-1].lower()

        ext = _get_ext(filename)
        max_bytes = int(config.max_bytes_image)
        if ext:
            try:
                import nsfw_scan  # noqa: WPS433

                if ext in nsfw_scan.VIDEO_EXTS:
                    max_bytes = int(config.max_bytes_video)
                elif ext in nsfw_scan.HEIF_EXTS:
                    max_bytes = int(config.max_bytes_image)
            except Exception:
                pass

        tmp_path, download_error = _download_remote_to_temp(
            session=session,
            base_url=base_url,
            remote_path=remote_path,
            suffix=suffix,
            max_bytes=max_bytes,
        )

        dir_path, name = _remote_dir_and_name(remote_path)
        if download_error:
            decision = "skipped" if download_error == "too_large" else "error"
            if decision == "skipped":
                self._inc("skipped", 1)
            else:
                self._inc("errors", 1)
            self._upsert_fn(
                target_id=target_id,
                remote_path=remote_path,
                dir_path=dir_path,
                filename=name,
                media_type=None,
                score=None,
                threshold=float(config.threshold),
                decision=decision,
                model="opennsfw2",
                details_json=None,
                error=download_error,
            )
            return

        try:
            sem = self._score_sem
            if sem is not None:
                sem.acquire()
            try:
                import nsfw_scan  # noqa: WPS433

                result = nsfw_scan.score_file(tmp_path)
            finally:
                if sem is not None:
                    try:
                        sem.release()
                    except Exception:
                        pass

            score = result.get("score")
            media_type = result.get("media_type")
            details = result.get("details") if isinstance(result.get("details"), dict) else {}
            details_json = nsfw_scan.dumps_details(details) if details else None

            decision = "unsupported"
            if score is None:
                decision = "unsupported" if media_type == "unsupported" else "error"
            else:
                decision = "nsfw" if float(score) >= float(config.threshold) else "clean"

            self._inc("files_scored", 1)
            if decision == "nsfw":
                self._inc("flagged", 1)
            elif decision == "error":
                self._inc("errors", 1)

            self._upsert_fn(
                target_id=target_id,
                remote_path=remote_path,
                dir_path=dir_path,
                filename=name,
                media_type=media_type,
                score=float(score) if score is not None else None,
                threshold=float(config.threshold),
                decision=decision,
                model="opennsfw2",
                details_json=details_json,
                error=None,
            )
        except Exception as e:
            self._inc("errors", 1)
            self._upsert_fn(
                target_id=target_id,
                remote_path=remote_path,
                dir_path=dir_path,
                filename=name,
                media_type=None,
                score=None,
                threshold=float(config.threshold),
                decision="error",
                model="opennsfw2",
                details_json=None,
                error=str(e),
            )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass


default_scanner = NsfwBatchScanner()
