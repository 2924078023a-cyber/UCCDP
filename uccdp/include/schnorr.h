/* include/schnorr.h */
#ifndef SCHNORR_H
#define SCHNORR_H

#include "Curve_MCL.h"

// Schnorr 签名结构
struct SchnorrSignature {
    G1Point R; // 随机项 R = r*G
    Fr s;      // 响应 s = r + c*x

    // 序列化大小 (用于统计)
    size_t get_size_bytes() {
        // [修改] 使用统一的 get_mcl_size
        return get_mcl_size(R) + get_mcl_size(s);
    }
};

class SchnorrSig {
public:
    G1Point g; // 生成元

    SchnorrSig();
    ~SchnorrSig();

    void setup();
    void keygen(Fr& sk, G1Point& pk);
    void sign(SchnorrSignature& sig, const Fr& sk, const std::string& msg);
    bool verify(const G1Point& pk, const SchnorrSignature& sig, const std::string& msg);
};

#endif