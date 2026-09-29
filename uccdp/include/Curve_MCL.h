/* include/Curve_MCL.h */
#ifndef CURVE_MCL_H
#define CURVE_MCL_H

#include <mcl/bls12_381.hpp>
#include <iostream>
#include <string>
#include <vector>

// 使用 BLS12-381 参数空间
using namespace mcl::bn;

// 简写类型
typedef Fr ZkScalar; // 标量域 (Zr)
typedef G1 G1Point;  // G1 群元素
typedef G2 G2Point;  // G2 群元素

// 全局初始化函数
inline void init_curve_env() {
    static bool inited = false;
    if (!inited) {
        initPairing(mcl::BLS12_381);
        inited = true;
    }
}

// === [新增] 统一的大小获取辅助函数 ===
// 解决 API 命名不一致问题

// 1. 对于标量 Fr，固定为 32 字节
inline size_t get_mcl_size(const Fr& fr) {
    return 32; 
}

// 2. 对于 G1 点，调用 getSerializedByteSize (48 bytes)
inline size_t get_mcl_size(const G1Point& p) {
    return p.getSerializedByteSize();
}

// 3. 对于 G2 点，调用 getSerializedByteSize (96 bytes)
inline size_t get_mcl_size(const G2Point& p) {
    return p.getSerializedByteSize();
}

#endif