# IronRoot 双栈 IP 地址分配库

纯 Python 3 标准库实现（仅依赖 `ipaddress`、`bisect`），状态全部保存在内存中。
支持 IPv4/IPv6 命名子网池（可重叠、可重复 CIDR）与全局保留地址区间，
提供地址分配、释放和精确容量查询。

## 文件

- `ironroot.py` — 库本体，导出 `IronRootAllocator` 与 `PoolStats`
- `test_ironroot.py` — 自动化测试（`unittest`）

## 快速开始

```python
from ironroot import IronRootAllocator

allocator = IronRootAllocator(
    pools={
        "office": "10.0.0.0/24",
        "dmz": "10.0.0.128/25",      # 可与 office 重叠
        "v6": "2001:db8::/64",
    },
    reserved=[("10.0.0.1", "10.0.0.1")],  # 同族闭区间，可相交/相邻
)

allocator.assign("office")                 # '10.0.0.2'（池内最小可用地址）
allocator.assign("office", "10.0.0.50")    # 指定地址；不可用则返回 None
allocator.assign("v6")                     # '2001:db8::'
allocator.release("10.0.0.2")              # 立即重新参与分配与计数

stats = allocator.stats("office")
stats.remaining                            # 精确剩余数量（int）
stats.min_available                        # 当前最小可用地址（str 或 None）
```

## 规则摘要

- 池的可用集合 = 池规则允许的地址 − 全局保留区间 − 全部存活分配；
  同一地址不会被不同池重复分配，重叠池的查询结果始终实时一致。
- IPv4 前缀长度 ≤ 30 时排除该池自身的网络地址与广播地址（仅作用于该池）；
  /31 两个地址、/32 单个地址均可用。IPv6 不排除任何端点，/128 可分配。
- IPv4 与 IPv6 为独立地址空间；同一 IPv6 地址的不同文本写法视为同一地址。
- 计数与区间运算全程使用任意精度整数，支持 IPv6 /0（剩余量恰为 2**128）
  以及包含最大 IPv6 地址的保留区间。
- 初始化后配置不可变；`assign` 无可用地址时返回 `None`；
  `release` 假定调用方只释放当前已分配的地址。

## 运行测试

```sh
python3 -m unittest test_ironroot -v
```

测试覆盖：小型重叠 IPv4 池（/30、/31、/32、跨池端点复用）上对照可穷举
参考模型的随机分配/释放/查询核对，以及 IPv6 /0 池中跨巨大地址空间的
相交保留区间、精确计数、最大地址边界、跨池冲突与释放后重分配。
