"""Tests for the IronRoot allocator."""

import ipaddress
import random
import unittest

from ironroot import IronRootAllocator, PoolStats

V4_POOLS = {
    "net30": "10.0.0.0/30",   # usable: .1, .2
    "net31": "10.0.0.0/31",   # usable: .0, .1 (endpoints allowed)
    "host32": "10.0.0.3/32",  # usable: .3 (broadcast of net30, fine here)
    "net29": "10.0.0.0/29",   # usable: .1 - .6
    "dup30": "10.0.0.0/30",   # same CIDR as net30
}
V4_RESERVED = [("10.0.0.4", "10.0.0.5"), ("10.0.0.5", "10.0.0.5")]


def allowed_set(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    lo = int(net.network_address)
    hi = int(net.broadcast_address)
    if net.version == 4 and net.prefixlen <= 30:
        lo += 1
        hi -= 1
    return set(range(lo, hi + 1))


class Model:
    """Exhaustive reference model over small pools."""

    def __init__(self, pools, reserved):
        self.allowed = {pid: allowed_set(cidr) for pid, cidr in pools.items()}
        self.reserved = set()
        for start, end in reserved:
            a = ipaddress.ip_address(start)
            b = ipaddress.ip_address(end)
            self.reserved.update(range(int(a), int(b) + 1))
        self.assigned = set()

    def available(self, pool_id):
        return self.allowed[pool_id] - self.reserved - self.assigned

    def stats(self, pool_id):
        avail = self.available(pool_id)
        lowest = min(avail) if avail else None
        return len(avail), lowest

    def assign_auto(self, pool_id):
        avail = self.available(pool_id)
        if not avail:
            return None
        value = min(avail)
        self.assigned.add(value)
        return value

    def assign_specific(self, pool_id, value):
        if value not in self.available(pool_id):
            return None
        self.assigned.add(value)
        return value

    def release(self, value):
        self.assigned.discard(value)


def fmt4(value):
    return str(ipaddress.IPv4Address(value))


class OverlappingIPv4ModelTest(unittest.TestCase):
    """Random op sequences on small overlapping pools vs. exhaustive model."""

    def run_sequence(self, seed, steps):
        rng = random.Random(seed)
        alloc = IronRootAllocator(V4_POOLS, V4_RESERVED)
        model = Model(V4_POOLS, V4_RESERVED)
        pool_ids = sorted(V4_POOLS)
        # candidate space: whole /29 plus neighbors outside every pool
        candidates = [int(ipaddress.IPv4Address(f"10.0.0.{i}")) for i in range(10)]

        for _ in range(steps):
            op = rng.randrange(4)
            if op == 0:
                pid = rng.choice(pool_ids)
                got = alloc.assign(pid)
                want = model.assign_auto(pid)
                self.assertEqual(got, None if want is None else fmt4(want))
            elif op == 1:
                pid = rng.choice(pool_ids)
                value = rng.choice(candidates)
                got = alloc.assign(pid, fmt4(value))
                want = model.assign_specific(pid, value)
                self.assertEqual(got, None if want is None else fmt4(want))
            elif op == 2:
                if model.assigned:
                    value = rng.choice(sorted(model.assigned))
                    alloc.release(fmt4(value))
                    model.release(value)
            else:
                pid = rng.choice(pool_ids)
                stats = alloc.stats(pid)
                want_count, want_min = model.stats(pid)
                self.assertEqual(stats.remaining, want_count)
                self.assertEqual(
                    stats.min_available, None if want_min is None else fmt4(want_min)
                )

        # final full sweep: every pool's stats must match the model exactly
        for pid in pool_ids:
            stats = alloc.stats(pid)
            want_count, want_min = model.stats(pid)
            self.assertEqual(stats.remaining, want_count)
            self.assertEqual(
                stats.min_available, None if want_min is None else fmt4(want_min)
            )

    def test_random_sequences(self):
        for seed in range(20):
            with self.subTest(seed=seed):
                self.run_sequence(seed, steps=500)

    def test_endpoint_rules_explicit(self):
        alloc = IronRootAllocator(V4_POOLS, V4_RESERVED)
        # /30 network address is excluded there but usable in the /31 pool
        self.assertEqual(alloc.assign("net30", "10.0.0.0"), None)
        self.assertEqual(alloc.assign("net31", "10.0.0.0"), "10.0.0.0")
        # /30 broadcast address is excluded there but usable via the /32 pool
        self.assertEqual(alloc.assign("net30", "10.0.0.3"), None)
        self.assertEqual(alloc.assign("host32"), "10.0.0.3")
        # same address cannot be handed out twice through different pools
        self.assertEqual(alloc.assign("net29", "10.0.0.0"), None)
        self.assertEqual(alloc.assign("dup30", "10.0.0.3"), None)
        # reserved interval is excluded everywhere
        self.assertEqual(alloc.assign("net29", "10.0.0.4"), None)
        self.assertEqual(alloc.assign("net29", "10.0.0.5"), None)
        self.assertEqual(alloc.assign("net29", "10.0.0.6"), "10.0.0.6")

    def test_release_reopens_lower_address(self):
        alloc = IronRootAllocator({"p": "10.0.0.0/30"}, None)
        self.assertEqual(alloc.assign("p"), "10.0.0.1")
        self.assertEqual(alloc.assign("p"), "10.0.0.2")
        self.assertIsNone(alloc.assign("p"))
        alloc.release("10.0.0.1")
        # auto allocation must not skip past the freed lower address
        self.assertEqual(alloc.assign("p"), "10.0.0.1")
        self.assertEqual(alloc.stats("p"), PoolStats(remaining=0, min_available=None))


class IPv6ScaleTest(unittest.TestCase):
    """Exact arithmetic over huge IPv6 ranges."""

    RESERVED = [
        ("2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
        ("2001:db8:8000::", "2001:db9::ffff"),  # intersects the previous one
        ("ffff:ffff:ffff:fffe::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ]

    @staticmethod
    def merged_size(intervals):
        spans = sorted(
            (int(ipaddress.IPv6Address(a)), int(ipaddress.IPv6Address(b)))
            for a, b in intervals
        )
        total = 0
        cur_lo, cur_hi = spans[0]
        for lo, hi in spans[1:]:
            if lo <= cur_hi + 1:
                cur_hi = max(cur_hi, hi)
            else:
                total += cur_hi - cur_lo + 1
                cur_lo, cur_hi = lo, hi
        return total + cur_hi - cur_lo + 1

    def test_empty_slash0_exact_count(self):
        alloc = IronRootAllocator({"all": "::/0"}, None)
        stats = alloc.stats("all")
        self.assertEqual(stats.remaining, 1 << 128)
        self.assertEqual(stats.min_available, "::")

    def test_huge_intersecting_reserved_exact_count(self):
        alloc = IronRootAllocator({"all": "::/0"}, self.RESERVED)
        expected = (1 << 128) - self.merged_size(self.RESERVED)
        self.assertEqual(alloc.stats("all").remaining, expected)
        alloc.assign("all", "2001:db9::1:0")  # just above the merged reserved span
        alloc.assign("all", "::1")
        self.assertEqual(alloc.stats("all").remaining, expected - 2)

    def test_max_address_boundary(self):
        alloc = IronRootAllocator({"all": "::/0"}, self.RESERVED)
        top = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        self.assertIsNone(alloc.assign("all", top))  # reserved
        just_below = "ffff:ffff:ffff:fffd:ffff:ffff:ffff:ffff"
        self.assertEqual(alloc.assign("all", just_below), just_below)
        # a reserved interval ending exactly at the max address is counted
        stats = alloc.stats("all")
        expected = (1 << 128) - self.merged_size(self.RESERVED) - 1
        self.assertEqual(stats.remaining, expected)

    def test_cross_pool_conflict_and_textual_variants(self):
        alloc = IronRootAllocator(
            {"a": "::/0", "b": "::/0", "low": "::/64"}, self.RESERVED
        )
        self.assertEqual(alloc.assign("a", "2001:0DB7:0000:0000::1"), "2001:db7::1")
        # same address, different spelling, different pool -> conflict
        self.assertIsNone(alloc.assign("b", "2001:db7:0:0:0:0:0:1"))
        # an address taken through the /0 pool blocks the overlapping /64 pool
        self.assertEqual(alloc.assign("a", "::1"), "::1")
        self.assertIsNone(alloc.assign("low", "::1"))
        # stats of every overlapping pool see the live allocation
        for pid in ("a", "b"):
            self.assertEqual(
                alloc.stats(pid).remaining,
                (1 << 128) - self.merged_size(self.RESERVED) - 2,
            )
        # release via yet another spelling, then the other pool can take it
        alloc.release("2001:db7:0:0:0:0:0:1")
        self.assertEqual(alloc.assign("b", "2001:db7::1"), "2001:db7::1")

    def test_release_low_address_then_reassign(self):
        alloc = IronRootAllocator({"low": "::/64"}, None)
        first = alloc.assign("low")
        second = alloc.assign("low")
        third = alloc.assign("low")
        self.assertEqual((first, second, third), ("::", "::1", "::2"))
        alloc.release("0:0:0:0:0:0:0:1")  # spelled-out "::1"
        self.assertEqual(alloc.stats("low").min_available, "::1")
        self.assertEqual(alloc.assign("low"), "::1")
        self.assertEqual(alloc.stats("low").remaining, (1 << 64) - 3)

    def test_ipv6_no_endpoint_exclusion(self):
        alloc = IronRootAllocator({"net": "2001:db8::/126", "host": "2001:db8::/128"}, None)
        self.assertEqual(alloc.stats("net").remaining, 4)  # /126: all 4 usable
        self.assertEqual(alloc.assign("net"), "2001:db8::")  # "network" address usable
        self.assertIsNone(alloc.assign("host"))  # already taken via the other pool
        alloc.release("2001:db8::")
        self.assertEqual(alloc.assign("host"), "2001:db8::")


if __name__ == "__main__":
    unittest.main()
