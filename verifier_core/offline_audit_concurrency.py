"""Job-local admission control for offline HTTP audits; no training hooks."""
from collections import Counter, deque
import json
from pathlib import Path
import threading
import time
import urllib.error


class AdaptiveRequestGate:
    def __init__(self, control, workers, request, save, clock=time.time, http_error_observer=None):
        self.control = Path(control)
        self.workers = workers
        self.request = request
        self.save = save
        self.clock = clock
        self.http_error_observer = http_error_observer
        self.condition = threading.Condition()
        self.active = self.peak = 0
        self.target = self.effective = min(8, workers)
        self.generation = 0
        self.revision = None
        self.last_read = self.last_save = 0
        self.last_raise = self.clock()
        self.last_reduce = self.last_raise - 10
        self.cooldown_until = 0
        self.totals = Counter()
        self.recent = deque()
        self.started = self.clock()
        self.last_success = self.last_failure = None
        self._refresh(force=True)
        self._publish(force=True)

    def _refresh(self, force=False):
        now = self.clock()
        if not force and now - self.last_read < 1:
            return
        self.last_read = now
        try:
            settings = json.loads(self.control.read_text())
            target = settings['target_inflight']
            if type(target) is not int or not 1 <= target <= self.workers:
                raise ValueError('invalid target_inflight')
            revision = (settings.get('revision'), target)
            if revision != self.revision:
                self.target = self.effective = target
                self.generation += 1
                self.revision = revision
                self.last_raise = now
            self.auto_raise = settings.get('auto_raise', False) is True
        except (OSError, ValueError, KeyError, TypeError):
            self.auto_raise = False  # Keep the last good limit on a malformed edit.
        # At one in-flight request, a 20s judge cannot finish 30 requests in
        # three minutes. Require evidence proportional to the reduced limit,
        # otherwise a recovered endpoint would stay throttled indefinitely.
        while self.recent and self.recent[0]['time'] < now - 180:
            self.recent.popleft()
        recovery_successes = min(30, max(3, self.effective * 2))
        recent_errors = any(e['outcome'] != 'ok' and e['time'] >= now - 60
                            for e in self.recent)
        if (self.auto_raise and self.effective < self.target and not recent_errors
                and now - max(self.last_reduce, self.last_raise) >= 180
                and sum(e['outcome'] == 'ok' for e in self.recent) >= recovery_successes):
            self.effective = min(self.target, self.effective + 4)
            self.generation += 1
            self.last_raise = now

    def _metrics(self):
        now = self.clock()
        while self.recent and self.recent[0]['time'] < now - 180:
            self.recent.popleft()
        window = list(self.recent)
        latencies = sorted(e['http_seconds'] for e in window if e['outcome'] == 'ok')
        span = min(180, max(1, now - self.started))
        return {'updated_unix': now, 'workers': self.workers,
                'started_unix': self.started,
                'last_successful_response_unix': self.last_success,
                'last_failed_response_unix': self.last_failure,
                'target_inflight': self.target, 'effective_inflight': self.effective,
                'active': self.active, 'peak_active': self.peak,
                'limit_generation': self.generation,
                'cooldown_until': self.cooldown_until, 'totals': dict(self.totals),
                'recent_window_seconds': span,
                'recent_outcomes': dict(Counter(e['outcome'] for e in window)),
                'recent_successful_http_per_hour': len(latencies) * 3600 / span,
                'recent_http_p50_seconds': latencies[len(latencies) // 2] if latencies else None,
                'recent_http_p95_seconds': latencies[int(.95 * (len(latencies) - 1))] if latencies else None}

    def _publish(self, force=False):
        now = self.clock()
        if force or now - self.last_save >= 2:
            self.save(self.control.with_name('concurrency_metrics.json'), self._metrics())
            self.last_save = now

    def _record(self, started, outcome, http_seconds, retry_after=0,
                admitted_limit=None, generation=None):
        now = self.clock()
        if outcome == 'ok':
            self.last_success = now
        else:
            self.last_failure = now
        generation = self.generation if generation is None else generation
        event = {'time': now, 'started_unix': started, 'http_seconds': http_seconds,
                 'outcome': outcome, 'limit': self.effective if admitted_limit is None else admitted_limit,
                 'limit_generation': generation}
        self.recent.append(event)
        self.totals[outcome] += 1
        while self.recent and self.recent[0]['time'] < now - 180:
            self.recent.popleft()
        done = [e for e in self.recent if e['time'] >= now - 60
                and e.get('limit_generation') == self.generation]
        bad = [e for e in done if e['outcome'] != 'ok']
        overloaded = generation == self.generation and (outcome == 'http_429' or
                      (outcome != 'ok' and len(bad) >= 3 and len(bad) / max(1, len(done)) >= .05))
        if overloaded and now - self.last_reduce >= 10:
            self.effective = max(1, self.effective // 2)
            self.generation += 1
            self.last_reduce = now
            self.totals['automatic_reductions'] += 1
        if outcome == 'http_429':
            self.cooldown_until = max(self.cooldown_until, now + max(10, min(120, retry_after)))
        with self.control.with_name('http_events.jsonl').open('a') as stream:
            stream.write(json.dumps(event) + '\n')

    def __call__(self, payload, cfg):
        waiting = self.clock()
        with self.condition:
            while True:
                self._refresh()
                if self.active < self.effective and self.clock() >= self.cooldown_until:
                    self.active += 1
                    admitted_limit, generation = self.effective, self.generation
                    self.peak = max(self.peak, self.active)
                    self._publish()
                    break
                self._publish()
                self.condition.wait(timeout=1)
        admitted = self.clock()
        outcome, retry_after = 'ok', 0
        try:
            response = self.request(payload, cfg)
            response.setdefault('_audit_timing', {})['offline_gate_queue_seconds'] = admitted - waiting
            return response
        except urllib.error.HTTPError as exc:
            outcome = 'http_' + str(exc.code)
            if self.http_error_observer is not None:
                try:
                    self.http_error_observer(exc, cfg)
                except Exception:
                    pass  # Diagnostics never replace the original HTTP failure.
            try:
                retry_after = float(exc.headers.get('Retry-After', 0))
            except (ValueError, TypeError, AttributeError):
                pass
            raise
        except Exception as exc:
            outcome = type(exc).__name__
            raise
        finally:
            with self.condition:
                self.active -= 1
                self._record(admitted, outcome, self.clock() - admitted, retry_after,
                             admitted_limit, generation)
                self._publish(force=True)
                self.condition.notify_all()

    def metrics(self):
        with self.condition:
            return self._metrics()
