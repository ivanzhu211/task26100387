"""IronRoot: dual-stack (IPv4/IPv6) in-memory IP address allocation library.

Semantics:
- Pools are named CIDRs; they may overlap or share the same CIDR.
- Global reserved intervals (inclusive, per address family) are excluded from
  every pool of that family.
- IPv4 pools with prefix length <= 30 exclude their own network and broadcast
  addresses; /31 and /32 pools may use every address. IPv6 pools never exclude
  endpoints.
- An address can be allocated only once across all pools of its family.
"""

from __future__ import annotations

import bisect
import ipaddress
from typing import Dict, Iterable, List, NamedTuple, Optional, Set, Tuple, Union

AddressLike = Union[str, int, ipaddress.IPv4Address, ipaddress.IPv6Address]
ReservedInterval = Tuple[AddressLike, AddressLike]

_V4 = 4
_V6 = 6
_MAX = {_V4: (1 << 32) - 1, _V6: (1 << 128) - 1}


class PoolStats(NamedTuple):
    """Snapshot of a pool: exact remaining count and smallest free address."""

    remaining: int
    min_available: Optional[str]


class _Pool(NamedTuple):
    version: int
    lo: int  # first usable address (inclusive)
    hi: int  # last usable address (inclusive)


def _parse(address: AddressLike) -> Tuple[int, int]:
    """Normalize an address to (version, integer value)."""
    if isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return address.version, int(address)
    if isinstance(address, str):
        parsed = ipaddress.ip_address(address)
        return parsed.version, int(parsed)
    if isinstance(address, int):
        if address < 0 or address > _MAX[_V6]:
            raise ValueError(f"address integer out of range: {address}")
        return (_V4, address) if address <= _MAX[_V4] else (_V6, address)
    raise TypeError(f"unsupported address type: {type(address)!r}")


def _format(version: int, value: int) -> str:
    cls = ipaddress.IPv4Address if version == _V4 else ipaddress.IPv6Address
    return str(cls(value))


def _pool_range(cidr: str) -> _Pool:
    net = ipaddress.ip_network(cidr, strict=False)
    lo = int(net.network_address)
    hi = int(net.broadcast_address)
    if net.version == _V4 and net.prefixlen <= 30:
        lo += 1
        hi -= 1
    return _Pool(net.version, lo, hi)


def _merge_intervals(intervals: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    merged: List[List[int]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1] + 1:
            if end > merged[-1][1]:
                merged[-1][1] = end
        else:
            merged.append([start, end])
    return [(start, end) for start, end in merged]


class IronRootAllocator:
    """In-memory dual-stack IP allocator over named, possibly overlapping pools."""

    def __init__(
        self,
        pools: Dict[str, str],
        reserved: Optional[Iterable[ReservedInterval]] = None,
    ) -> None:
        if not pools:
            raise ValueError("at least one pool is required")
        self._pools: Dict[str, _Pool] = {}
        for pool_id, cidr in pools.items():
            if pool_id in self._pools:
                raise ValueError(f"duplicate pool id: {pool_id!r}")
            self._pools[pool_id] = _pool_range(cidr)

        per_family: Dict[int, List[Tuple[int, int]]] = {_V4: [], _V6: []}
        for item in reserved or ():
            start_addr, end_addr = item
            start_ver, start = _parse(start_addr)
            end_ver, end = _parse(end_addr)
            if start_ver != end_ver:
                raise ValueError(f"reserved interval mixes families: {item!r}")
            if start > end:
                raise ValueError(f"reserved interval start after end: {item!r}")
            per_family[start_ver].append((start, end))
        self._reserved: Dict[int, List[Tuple[int, int]]] = {
            version: _merge_intervals(intervals)
            for version, intervals in per_family.items()
        }
        self._reserved_starts: Dict[int, List[int]] = {
            version: [start for start, _ in intervals]
            for version, intervals in self._reserved.items()
        }
        self._assigned: Dict[int, Set[int]] = {_V4: set(), _V6: set()}

    # -- internal helpers -------------------------------------------------

    def _pool(self, pool_id: str) -> _Pool:
        try:
            return self._pools[pool_id]
        except KeyError:
            raise KeyError(f"unknown pool id: {pool_id!r}") from None

    def _reserved_count(self, version: int, lo: int, hi: int) -> int:
        """Exact count of reserved addresses within [lo, hi]."""
        intervals = self._reserved[version]
        starts = self._reserved_starts[version]
        total = 0
        index = bisect.bisect_right(starts, lo) - 1
        if index < 0:
            index = 0
        while index < len(intervals) and intervals[index][0] <= hi:
            start, end = intervals[index]
            total += min(end, hi) - max(start, lo) + 1
            index += 1
        return total

    def _is_reserved(self, version: int, value: int) -> bool:
        intervals = self._reserved[version]
        starts = self._reserved_starts[version]
        index = bisect.bisect_right(starts, value) - 1
        return index >= 0 and intervals[index][1] >= value

    def _min_available(self, pool: _Pool) -> Optional[int]:
        assigned = self._assigned[pool.version]
        candidate = pool.lo
        for start, end in self._reserved[pool.version]:
            if end < pool.lo:
                continue
            if start > pool.hi:
                break
            stop = min(start, pool.hi + 1)
            while candidate < stop:
                if candidate not in assigned:
                    return candidate
                candidate += 1
            candidate = max(candidate, end + 1)
        while candidate <= pool.hi:
            if candidate not in assigned:
                return candidate
            candidate += 1
        return None

    # -- public API -------------------------------------------------------

    def assign(self, pool_id: str, requested: Optional[AddressLike] = None) -> Optional[str]:
        """Allocate an address from a pool.

        Without ``requested`` picks the numerically smallest free address;
        otherwise tries exactly that address. Returns the canonical string
        form of the allocated address, or None if nothing could be allocated.
        """
        pool = self._pool(pool_id)
        if requested is None:
            value = self._min_available(pool)
            if value is None:
                return None
        else:
            if isinstance(requested, int) and not isinstance(
                requested, (ipaddress.IPv4Address, ipaddress.IPv6Address)
            ):
                if requested < 0 or requested > _MAX[pool.version]:
                    return None
                version, value = pool.version, requested
            else:
                version, value = _parse(requested)
            if version != pool.version:
                return None
            if not (pool.lo <= value <= pool.hi):
                return None
            if value in self._assigned[pool.version]:
                return None
            if self._is_reserved(pool.version, value):
                return None
        self._assigned[pool.version].add(value)
        return _format(pool.version, value)

    def release(self, address: AddressLike) -> None:
        """Release a currently allocated address back to every pool."""
        if isinstance(address, int) and not isinstance(
            address, (ipaddress.IPv4Address, ipaddress.IPv6Address)
        ):
            hits = [v for v in (_V4, _V6) if address in self._assigned[v]]
            if len(hits) != 1:
                raise ValueError(f"address not unambiguously allocated: {address!r}")
            self._assigned[hits[0]].discard(address)
            return
        version, value = _parse(address)
        if value not in self._assigned[version]:
            raise ValueError(f"address is not allocated: {address!r}")
        self._assigned[version].discard(value)

    def stats(self, pool_id: str) -> PoolStats:
        """Exact remaining address count and smallest free address of a pool."""
        pool = self._pool(pool_id)
        size = pool.hi - pool.lo + 1
        remaining = size - self._reserved_count(pool.version, pool.lo, pool.hi)
        assigned = self._assigned[pool.version]
        remaining -= sum(1 for value in assigned if pool.lo <= value <= pool.hi)
        lowest = self._min_available(pool)
        return PoolStats(
            remaining=remaining,
            min_available=None if lowest is None else _format(pool.version, lowest),
        )
