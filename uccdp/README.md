# UCCDP 源码（论文实验版）

UCCDP：一种无智能合约的隐私保护通用跨链延时支付协议——实验源码。

## 目录结构

```
include/    头文件（曲线环境、2AS 适配器签名、PS 盲签名、Schnorr、
            LHP 时间锁、Shamir 秘密分享、NIZK、VTD、工具函数）
src/        上述模块的实现
benchmarks/ 实验程序：
            benchmark_vtd.cpp       —— VTD 性能（表 4：n、T 扫描）
            benchmark_micro_ops.cpp —— 2AS/PS 原语级微基准（表 3）
            benchmark_phases.cpp    —— UCCDP 四阶段开销（图 10，本文方案）
```

## 依赖

- GMP（任意较新版本）
- OpenSSL（libcrypto）
- mcl（herumi mcl，BLS12-381 曲线）

## 编译示例（Linux）

```bash
# 表 4：VTD 基准
g++ -O2 -std=c++17 -Iinclude src/*.cpp benchmarks/benchmark_vtd.cpp \
    -lgmp -lcrypto -lmcl -o bench_vtd

# 表 3：微观操作基准
g++ -O2 -std=c++17 -Iinclude src/adaptor_sig.cpp src/ps_sig.cpp \
    src/schnorr.cpp src/util.cpp benchmarks/benchmark_micro_ops.cpp \
    -lgmp -lcrypto -lmcl -o bench_micro

# 图 10：四阶段开销
g++ -O2 -std=c++17 -Iinclude src/*.cpp benchmarks/benchmark_phases.cpp \
    -lgmp -lcrypto -lmcl -o bench_phases
```

（具体链接选项请按本机 mcl 安装方式调整，如使用 mcl 的静态库路径。）

## 运行说明

- 随机数：所有随机源均已由 /dev/urandom（回退 OpenSSL RAND_bytes）安全播种，
  每次运行结果为独立随机样本。
- 强素数：generate_strong_prime 采用 p = 2kq+1 结构，仅在 Setup 阶段调用，
  不计入 Commit/Verify/Solve 等计时指标，但会使程序启动慢数秒，属正常现象。
- benchmark_vtd 的 Solve 计时后自带正确性校验（恢复值 == w mod N），
  若输出 [警告] 说明 LHP 实现有误。
