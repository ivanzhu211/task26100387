# IronRoot

双栈（IPv4/IPv6）内存 IP 地址分配库，仅依赖 Python 3 标准库（`ipaddress`）。
支持重叠/相同 CIDR 的具名地址池、全局保留区间、精确容量查询。

## 文件

- `ironroot.py` — 库本体，导出 `IronRootAllocator` 与 `PoolStats`
- `test_ironroot.py` — 自动化测试（`python3 -m unittest test_ironroot -v`）

## 快速上手

```python
from ironroot import IronRootAllocator

alloc = IronRootAllocator(
    pools={
        "office": "10.0.0.0/29",     # 可用 .1 - .6（排除本池网络/广播地址）
        "p2p": "10.0.0.0/31",        # /31 两个地址均可用
        "v6": "2001:db8::/64",       # IPv6 不排除任何端点
    },
    reserved=[("10.0.0.1", "10.0.0.1")],  # 全局保留闭区间，按地址族生效
)

alloc.assign("office")                 # '10.0.0.2'（数值最小的可用地址）
alloc.assign("office", "10.0.0.5")     # 指定地址；不可用则返回 None
alloc.assign("v6")                     # '2001:db8::'
alloc.release("10.0.0.2")              # 立即重新参与分配与计数
stats = alloc.stats("office")          # PoolStats(remaining=4, min_available='10.0.0.2')
```

## 语义要点

- 池可重叠或相同；同一地址不会被不同的池重复分配。
- 保留区间是同地址族的闭区间，可相交或相邻（初始化时自动合并），
  从所有同族池中排除；初始化后配置不可变。
- IPv4 前缀长度 ≤ 30 时排除该池自己的网络地址与广播地址；/31、/32 全部可用。
  端点排除只作用于本池：一个地址可以是某池的网络地址，同时是另一池的合法主机地址。
- IPv6 不自动排除端点，/128 可分配；空 ::/0 池剩余数量恰为 2**128。
- IPv4 与 IPv6 是独立地址空间；同一 IPv6 地址的不同文本写法视为同一地址。
- 地址参数接受字符串、整数或 `ipaddress` 地址对象；返回值与 `min_available`
  均为规范化字符串（IPv6 为压缩形式），池耗尽时为 `None`。
- `release` 仅应对当前已分配的地址调用，否则抛出 `ValueError`。

## 运行测试

```sh
python3 -m unittest test_ironroot -v
```
