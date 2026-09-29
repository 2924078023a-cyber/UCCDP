/* include/ps_sig.h - 基于 BLS12-381 的 PS 盲签名 */
#ifndef PS_SIG_H
#define PS_SIG_H

#include "Curve_MCL.h"

class PSSig {
public:
    // 生成元
    G1Point g;      // G1 生成元
    G2Point gt_gen; // G2 生成元 (对应论文中的 g~)

    // 密钥
    Fr x, y;             // SK
    G2Point X_tilde, Y_tilde; // PK (在 G2)
    
    // 签名者辅助 (用于 Sign 算法)
    G1Point X_G1, Y_G1;

    PSSig();
    ~PSSig();

    void setup();
    void keygen();

    // Commit: 盲化 m
    // com = t*g + m*Y_G1 (这里按照你之前的逻辑: g^t * Y^m)
    // 输出: com
    void commit(G1Point& com, const Fr& m, const Fr& t);

    // Sign (Blind Sign)
    // 输入: com
    // 输出: sigma1, sigma2
    void sign(G1Point& sigma1, G1Point& sigma2, const G1Point& com);

    // Unblind
    // 解盲: sigma2 = sigma2_blind - t * sigma1
    void unblind(G1Point& sigma1, G1Point& sigma2, 
                 const G1Point& sigma1_prime, const G1Point& sigma2_prime, const Fr& t);

    // Verify
    // e(sigma1, X~ + m*Y~) == e(sigma2, g~)
    bool verify(const Fr& m, const G1Point& sigma1, const G1Point& sigma2);
};

#endif