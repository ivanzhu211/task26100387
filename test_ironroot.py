"""Tests for the IronRoot dual-stack IP allocator."""

import ipaddress
import random
import unittest

from ironroot import IronRootAllocator


def _reference_allowed(cidr, reserved):
    """Usable address set of one pool: pool rules minus reserved intervals."""
    network = ipaddress.ip_network(cidr)
    lo = int(network.network_address)
    hi = int(network.broadcast_address)
    if network.version == 4 and network.prefixlen <= 30:
        lo += 1
        hi -= 1
    allowed = set(range(lo, hi + 1))
    for start, end in reserved:
        start = ipaddress.ip_address(start)
        end = ipaddress.ip_address(end)
        if start.version != network.version:
            continue
        allowed -= set(range(int(start), int(end) + 1))
    return allowed


class ReferenceModel:
    """Exhaustible set-based model mirroring the spec rules."""

    def __init__(self, pools, reserved):
        self.allowed = {
            pool_id: _reference_allowed(cidr, reserved)
            for pool_id, cidr in pools.items()
        }
        self.allocated = set()

    def assign(self, pool_id, requested=None):
        available = self.allowed[pool_id] - self.allocated
        if requested is not None:
            value = int(ipaddress.ip_address(requested))
            if value not in available:
                return None
            self.allocated.add(value)
            return str(ipaddress.ip_address(requested))
        if not available:
            return None
        value = min(available)
        self.allocated.add(value)
        return str(ipaddress.ip_address(value))

    def release(self, address):
        self.allocated.discard(int(ipaddress.ip_address(address)))

    def stats(self, pool_id):
        available = self.allowed[pool_id] - self.allocated
        minimum = min(available) if available else None
        return len(available), (
            str(ipaddress.ip_address(minimum)) if minimum is not None else None
        )


IPV4_POOLS = {
    "wide": "10.0.0.0/29",      # hosts .1-.6
    "sub30": "10.0.0.4/30",     # hosts .5-.6
    "pair31": "10.0.0.6/31",    # both .6 and .7 usable
    "single32": "10.0.0.7/32",  # .7 usable
    "edge30": "10.0.0.0/30",    # hosts .1-.2; its broadcast .3 is a host in "wide"
}
IPV4_RESERVED = [("10.0.0.2", "10.0.0.2")]


class TestIPv4AgainstReferenceModel(unittest.TestCase):
    def setUp(self):
        self.allocator = IronRootAllocator(IPV4_POOLS, reserved=IPV4_RESERVED)
        self.model = ReferenceModel(IPV4_POOLS, IPV4_RESERVED)

    def check_all_stats(self):
        for pool_id in IPV4_POOLS:
            expected_count, expected_min = self.model.stats(pool_id)
            actual = self.allocator.stats(pool_id)
            self.assertEqual(actual.remaining, expected_count, pool_id)
            self.assertEqual(actual.min_available, expected_min, pool_id)

    def test_randomized_operations(self):
        rng = random.Random(20261003)
        pool_ids = sorted(IPV4_POOLS)
        live = []
        for step in range(600):
            action = rng.choice(["auto", "specific", "release"])
            if action == "release" and live:
                address = live.pop(rng.randrange(len(live)))
                self.allocator.release(address)
                self.model.release(address)
            elif action == "specific":
                pool_id = rng.choice(pool_ids)
                candidates = sorted(self.model.allowed[pool_id])
                requested = str(ipaddress.ip_address(rng.choice(candidates)))
                got = self.allocator.assign(pool_id, requested)
                want = self.model.assign(pool_id, requested)
                self.assertEqual(got, want, (pool_id, requested))
                if got is not None:
                    live.append(got)
            else:
                pool_id = rng.choice(pool_ids)
                got = self.allocator.assign(pool_id)
                want = self.model.assign(pool_id)
                self.assertEqual(got, want, pool_id)
                if got is not None:
                    live.append(got)
            self.check_all_stats()

    def test_endpoint_of_one_pool_is_host_in_another(self):
        # 10.0.0.3 is the broadcast address of edge30 (10.0.0.0/30)
        # but a regular host address of wide (10.0.0.0/29).
        self.assertIsNone(self.allocator.assign("edge30", "10.0.0.3"))
        self.assertEqual(self.allocator.assign("wide", "10.0.0.3"), "10.0.0.3")
        # 10.0.0.4 is the network address of sub30 but a host of wide... it is
        # also sub30's network address, so only "wide" may hand it out.
        self.assertIsNone(self.allocator.assign("sub30", "10.0.0.4"))
        self.assertEqual(self.allocator.assign("wide", "10.0.0.4"), "10.0.0.4")

    def test_slash31_and_slash32_endpoints_usable(self):
        self.assertEqual(self.allocator.assign("pair31", "10.0.0.6"), "10.0.0.6")
        self.assertEqual(self.allocator.assign("pair31", "10.0.0.7"), "10.0.0.7")
        self.assertIsNone(self.allocator.assign("pair31"))
        # .7 already taken via pair31: single32 overlaps and must see it.
        self.assertIsNone(self.allocator.assign("single32"))
        self.assertEqual(self.allocator.stats("single32").remaining, 0)
        self.allocator.release("10.0.0.7")
        self.assertEqual(self.allocator.assign("single32"), "10.0.0.7")

    def test_release_makes_address_reusable_everywhere(self):
        self.assertEqual(self.allocator.assign("wide"), "10.0.0.1")
        self.assertEqual(self.allocator.assign("wide"), "10.0.0.3")
        self.allocator.release("10.0.0.1")
        stats = self.allocator.stats("wide")
        self.assertEqual(stats.min_available, "10.0.0.1")
        self.assertEqual(self.allocator.assign("wide"), "10.0.0.1")


IPV6_MAX = 2**128 - 1


def _v6(text):
    return int(ipaddress.IPv6Address(text))


class TestIPv6HugeSpace(unittest.TestCase):
    def setUp(self):
        # Intersecting reserved intervals spanning an enormous range, plus one
        # interval that ends exactly at the maximum IPv6 address.
        self.reserved = [
            ("::1", "::ffff:ffff:ffff:ffff"),
            ("::ffff:ffff:ffff:fffe", "2001:db8::1"),
            ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe",
             "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        ]
        self.allocator = IronRootAllocator(
            {"all": "::/0", "site": "2001:db8::/64"},
            reserved=self.reserved,
        )

    def test_exact_count_with_intersecting_reserved(self):
        # Merged reserved: [::1, 2001:db8::1] plus the top two addresses.
        blocked = _v6("2001:db8::1") - _v6("::1") + 1 + 2
        stats = self.allocator.stats("all")
        self.assertEqual(stats.remaining, 2**128 - blocked)
        self.assertEqual(stats.min_available, "::")

    def test_empty_slash0_count(self):
        allocator = IronRootAllocator({"all": "::/0"})
        stats = allocator.stats("all")
        self.assertEqual(stats.remaining, 2**128)
        self.assertEqual(stats.min_available, "::")

    def test_max_address_boundary(self):
        top = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffd"
        self.assertEqual(self.allocator.assign("all", top), top)
        # The two highest addresses are reserved.
        self.assertIsNone(
            self.allocator.assign(
                "all", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"
            )
        )
        self.assertIsNone(
            self.allocator.assign(
                "all", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
            )
        )
        # The first address above the big reserved block is assignable.
        self.assertEqual(self.allocator.assign("all", "2001:db8::2"), "2001:db8::2")

    def test_cross_pool_conflict_and_text_forms(self):
        # Same address written differently is the same allocation.
        self.assertEqual(
            self.allocator.assign("site", "2001:0db8:0000:0000::5"),
            "2001:db8::5",
        )
        self.assertIsNone(self.allocator.assign("all", "2001:db8:0:0:0:0:0:5"))
        stats = self.allocator.stats("all")
        self.assertEqual(stats.remaining, 2**128 - (
            _v6("2001:db8::1") - _v6("::1") + 1 + 2
        ) - 1)

    def test_release_low_address_then_reassign(self):
        first = self.allocator.assign("all")
        self.assertEqual(first, "::")
        second = self.allocator.assign("all")
        self.assertEqual(second, "2001:db8::2")
        self.allocator.release("::")
        stats = self.allocator.stats("all")
        self.assertEqual(stats.min_available, "::")
        # Auto-assign must not skip over the freed lower address.
        self.assertEqual(self.allocator.assign("all"), "::")

    def test_site_pool_min_tracks_global_allocations(self):
        self.assertEqual(self.allocator.assign("all", "2001:db8::2"), "2001:db8::2")
        stats = self.allocator.stats("site")
        self.assertEqual(stats.min_available, "2001:db8::3")
        self.assertEqual(stats.remaining, 2**64 - 3)


if __name__ == "__main__":
    unittest.main()
