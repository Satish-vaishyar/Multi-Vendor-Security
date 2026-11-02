"""Entry point of the recurring cloud scan runner: ``python -m app.cloud_scheduler``. Idle (and harmless) unless
CLOUD_MODULE_ENABLED is on. Several copies may run at once: due rows are claimed with SKIP LOCKED."""
from __future__ import annotations
import logging
import signal
import threading

from app.core import cloud_runner

log = logging.getLogger("sih26155")
POLL_SECONDS = 60


def main() -> None:
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    log.info("cloud scheduler started (poll %ss)", POLL_SECONDS)
    while not stop.is_set():
        try:
            n = cloud_runner.tick()
            if n:
                log.info("cloud scheduler completed %d recurring scan(s)", n)
        except Exception:  # noqa: BLE001 - the loop must survive a bad tick
            log.exception("cloud scheduler tick failed")
        stop.wait(POLL_SECONDS)


if __name__ == "__main__":  # pragma: no cover
    main()
