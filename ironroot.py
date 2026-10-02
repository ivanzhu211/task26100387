"""IronRoot dual-stack IP address allocation library.

In-memory state only. Provides address assignment, release and exact
capacity queries over named, possibly overlapping CIDR pools, with
global reserved address intervals.
"""

from __future__ import annotations

import bisect
import ipaddress
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple

_ADDRESS_CLASS = {4: ipaddress.IPv4Address, 6: ipaddress.IPv6Address}


class PoolStats(NamedTuple):
    """Result of a capacity query on a pool."""

    remaining: int
    min_available: Optional[str]


class _IntervalSet:
    """Sorted set of disjoint, non-adjacent closed integer intervals."""

    def __init__(self) -> None:
        self._starts: List[int] = []
        self._ends: List[int] = []

    def _index_of(self, value: int) -> Optional[int]:
        """Index of the interval containing value, or None."""
        i = bisect.bisect_right(self._starts, value) - 1
        if i >= 0 and self._ends[i] >= value:
            return i
        return None

    def add_point(self, value: int) -> None:
        i = bisect.bisect_right(self._starts, value)
        left_merge = i > 0 and self._ends[i - 1] >= value - 1
        right_merge = i < len(self._starts) and self._starts[i] <= value + 1
        if left_merge and right_merge:
            self._ends[i - 1] = self._ends[i]
            del self._starts[i]
            del self._ends[i]
        elif left_merge:
            self._ends[i - 1] = max(self._ends[i - 1], value)
        elif right_merge:
            self._starts[i] = min(self._starts[i], value)
        else:
            self._starts.insert(i, value)
            self._ends.insert(i, value)

    def discard_point(self, value: int) -> None:
        i = self._index_of(value)
        if i is None:
            raise KeyError(value)
        lo, hi = self._starts[i], self._ends[i]
        if lo == hi:
            del self._starts[i]
            del self._ends[i]
        elif value == lo:
            self._starts[i] = lo + 1
        elif value == hi:
            self._ends[i] = hi - 1
        else:
            self._starts.insert(i + 1, value + 1)
            self._ends.insert(i + 1, hi)
            self._ends[i] = value - 1

    def contains(self, value: int) -> bool:
        return self._index_of(value) is not None

    def count_in(self, lo: int, hi: int) -> int:
        if lo > hi:
            return 0
        total = 0
        i = bisect.bisect_right(self._starts, hi)
        j = bisect.bisect_left(self._ends, lo)
        for k in range(j, i):
            total += min(self._ends[k], hi) - max(self._starts[k], lo) + 1
        return total

    def first_gap_in(self, lo: int, hi: int) -> Optional[int]:
        i = bisect.bisect_right(self._starts, lo) - 1
        if i >= 0 and self._ends[i] >= lo:
            candidate = self._ends[i] + 1
        else:
            candidate = lo
        return candidate if candidate <= hi else None


class _Pool:
    """Precomputed usable address ranges of one pool."""

    def __init__(self, cidr: str) -> None:
        network = ipaddress.ip_network(cidr)
        self.version = network.version
        lo = int(network.network_address)
        hi = int(network.broadcast_address)
        if network.version == 4 and network.prefixlen <= 30:
            lo += 1
            hi -= 1
        self.ranges: List[Tuple[int, int]] = [(lo, hi)] if lo <= hi else []


class IronRootAllocator:
    """Dual-stack IP allocator with named pools and reserved intervals."""

    def __init__(
        self,
        pools: Dict[str, str],
        reserved: Sequence[Tuple[str, str]] = (),
    ) -> None:
        reserved_by_version: Dict[int, List[Tuple[int, int]]] = {4: [], 6: []}
        for start_text, end_text in reserved:
            start = ipaddress.ip_address(start_text)
            end = ipaddress.ip_address(end_text)
            if start.version != end.version:
                raise ValueError("reserved interval mixes address families")
            lo, hi = int(start), int(end)
            if lo > hi:
                raise ValueError("reserved interval start exceeds end")
            reserved_by_version[start.version].append((lo, hi))

        self._pools: Dict[str, _Pool] = {}
        for pool_id, cidr in pools.items():
            pool = _Pool(cidr)
            pool.ranges = _subtract_intervals(
                pool.ranges, _merge_intervals(reserved_by_version[pool.version])
            )
            self._pools[pool_id] = pool

        self._allocated: Dict[int, _IntervalSet] = {4: _IntervalSet(), 6: _IntervalSet()}

    def assign(self, pool_id: str, requested: Optional[str] = None) -> Optional[str]:
        pool = self._pools[pool_id]
        allocated = self._allocated[pool.version]
        if requested is not None:
            address = ipaddress.ip_address(requested)
            value = int(address)
            if address.version != pool.version or allocated.contains(value):
                return None
            if not any(lo <= value <= hi for lo, hi in pool.ranges):
                return None
            allocated.add_point(value)
            return str(address)
        for lo, hi in pool.ranges:
            candidate = allocated.first_gap_in(lo, hi)
            if candidate is not None:
                allocated.add_point(candidate)
                return str(_ADDRESS_CLASS[pool.version](candidate))
        return None

    def release(self, address: str) -> None:
        parsed = ipaddress.ip_address(address)
        self._allocated[parsed.version].discard_point(int(parsed))

    def stats(self, pool_id: str) -> PoolStats:
        pool = self._pools[pool_id]
        allocated = self._allocated[pool.version]
        remaining = 0
        min_available: Optional[str] = None
        for lo, hi in pool.ranges:
            remaining += hi - lo + 1 - allocated.count_in(lo, hi)
            if min_available is None:
                gap = allocated.first_gap_in(lo, hi)
                if gap is not None:
                    min_available = str(_ADDRESS_CLASS[pool.version](gap))
        return PoolStats(remaining=remaining, min_available=min_available)


def _merge_intervals(intervals: Sequence[Tuple[int, int]]) -> List[Tuple[int, int]]:
    merged: List[Tuple[int, int]] = []
    for lo, hi in sorted(intervals):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def _subtract_intervals(
    ranges: Sequence[Tuple[int, int]],
    blocked: Sequence[Tuple[int, int]],
) -> List[Tuple[int, int]]:
    result: List[Tuple[int, int]] = []
    for lo, hi in ranges:
        cursor = lo
        for block_lo, block_hi in blocked:
            if block_hi < cursor:
                continue
            if block_lo > hi:
                break
            if block_lo > cursor:
                result.append((cursor, block_lo - 1))
            cursor = max(cursor, block_hi + 1)
            if cursor > hi:
                break
        if cursor <= hi:
            result.append((cursor, hi))
    return result
