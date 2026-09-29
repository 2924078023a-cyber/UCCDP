/* include/adaptor_sig.h */
#ifndef ADAPTOR_SIG_H
#define ADAPTOR_SIG_H

#include "Curve_MCL.h"

class AdaptorSig_Schnorr {
public:
    G1Point g; // 生成元

    AdaptorSig_Schnorr();
    ~AdaptorSig_Schnorr();

    void setup();

    // 1. 密钥生成
    void keygen(Fr& sk, G1Point& pk);

    // 2. 生成适配器秘密 (Witness)
    // y <- Random, Y = y * g
    void gen_secret_pair(Fr& y, G1Point& Y);

    // 3. 预签名 (Pre-Sign)
    // 输出: s_pre (标量), R_pre (G1点)
    void pre_sign(Fr& s_pre, G1Point& R_pre, const Fr& sk, const std::string& msg, const G1Point& Y);

    // 4. 预验证 (Pre-Verify)
    bool pre_verify(const G1Point& pk, const Fr& s_pre, const G1Point& R_pre, const std::string& msg, const G1Point& Y);

    // 5. 补全签名 (Adapt)
    // s = s_pre + y
    void adapt(Fr& s_full, const Fr& s_pre, const Fr& y);

    // 6. 提取秘密 (Extract)
    // y = s - s_pre
    void extract(Fr& y, const Fr& s_full, const Fr& s_pre);
};

#endif