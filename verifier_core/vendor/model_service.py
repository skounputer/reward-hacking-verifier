"""Explicit private model endpoints and a shared cross-process request limit."""
from contextlib import contextmanager
import fcntl
import ipaddress
import json
from pathlib import Path
import time
import urllib.request
from urllib.parse import urlsplit


def validate_model_endpoint(url, backend):
    parsed = urlsplit(url)
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Invalid model endpoint")
    if backend == "remote_api":
        if parsed.scheme != "https":
            raise ValueError("Remote model endpoint must use HTTPS")
    elif backend == "self_hosted":
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            raise ValueError("Self-hosted endpoint requires a literal private IP") from None
        if parsed.scheme != "http" or not (address.is_loopback or any(address in ipaddress.ip_network(network) for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))):
            raise ValueError("Self-hosted endpoint must use loopback or RFC 1918 private HTTP")
    else:
        raise ValueError("Unknown model backend")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def open_private_model(request, timeout):
    validate_model_endpoint(request.full_url, "self_hosted")
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(request, timeout=timeout)


def model_service_ready(marker, model, base_url):
    """A separate service allocation publishes this after health and real-input probes."""
    if not marker:
        return True
    try:
        ready = json.loads(Path(marker).read_text())
        return (isinstance(ready, dict) and ready.get("ready") is True and ready.get("model") == model
                and ready.get("base_url", "").rstrip("/") == base_url.rstrip("/"))
    except (OSError, ValueError, TypeError):
        return False


@contextmanager
def shared_model_slot(directory, limit=4, timeout=600):
    """Use the same directory for teacher and reward judge on every worker."""
    started = time.monotonic()
    if not directory:
        yield {"queue_seconds": 0.0}
        return
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    handle = None
    try:
        while handle is None:
            for index in range(limit):
                candidate = (root / str(index)).open("a+")
                try:
                    fcntl.flock(candidate, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    handle = candidate
                    break
                except BlockingIOError:
                    candidate.close()
            if handle is None:
                if time.monotonic() - started >= timeout:
                    raise TimeoutError("shared_model_queue_timeout")
                time.sleep(.1)
        yield {"queue_seconds": time.monotonic() - started}
    finally:
        if handle is not None:
            fcntl.flock(handle, fcntl.LOCK_UN)
            handle.close()
