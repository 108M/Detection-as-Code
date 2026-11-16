"""`dac lab replay`: replay a test dataset "now" so the deployed rules raise real alerts.

Events are written to winlogbeat-dac-replay-<dataset> (an index pattern the deployed
rules already read) with their timestamps compressed into the last few minutes,
keeping the original order, so the whole capture falls inside the rules' look-back
window (from: now-6m) on their next execution.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable

from elasticsearch import Elasticsearch, helpers

from dac.datasets import Dataset, iter_events

REPLAY_PREFIX = "winlogbeat-dac-replay-"
WINDOW = dt.timedelta(minutes=2)


def _parse(ts: str) -> dt.datetime:
    return dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))


def replay(
    es: Elasticsearch,
    ds: Dataset,
    log: Callable[[str], None] = print,
    now: dt.datetime | None = None,
) -> tuple[str, int]:
    events = list(iter_events(ds, log))
    if not events:
        return "", 0
    stamps = [_parse(e["@timestamp"]) for e in events]
    first, last = min(stamps), max(stamps)
    span = (last - first) or dt.timedelta(seconds=1)
    end = now or dt.datetime.now(dt.UTC)
    start = end - WINDOW
    for event, ts in zip(events, stamps, strict=True):
        new_ts = start + WINDOW * ((ts - first) / span)
        event["@timestamp"] = new_ts.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        event.setdefault("event", {})["original_timestamp"] = ts.isoformat()
    index = f"{REPLAY_PREFIX}{ds.id}".lower()
    es.indices.delete(index=index, ignore_unavailable=True)
    ok, _ = helpers.bulk(es, ({"_index": index, "_source": e} for e in events), chunk_size=2000)
    es.indices.refresh(index=index)
    return index, ok


def clean(es: Elasticsearch) -> int:
    indices = list(es.indices.get(index=f"{REPLAY_PREFIX}*", ignore_unavailable=True).keys())
    if indices:
        es.indices.delete(index=",".join(indices))
    return len(indices)
