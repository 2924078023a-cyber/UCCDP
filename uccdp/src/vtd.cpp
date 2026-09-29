#include "vtd.h"
#include "lhp.h"
#include "nizk.h"
#include "Shamir.h"
#include "util.h"
#include <vector>
#include <iostream>
#include <algorithm>  // <--- 加上这一行，爆红就会消失

VTD_crs_t::VTD_crs_t() { mpz_init(crs_range); }
VTD_crs_t::~VTD_crs_t() { mpz_clear(crs_range); }

void Setup_VTD(VTD_crs_t& crs, int lambda, unsigned long T) {
    ZKSetup(lambda, crs.crs_range);
    LHP_PSetup(crs.params, lambda, T);
}

void Commit_VTD(LHP_Puzzle* Z, Proof* proofs, mpz_t H, mpz_t* w_shares, mpz_t* H_shares, std::vector<int>& challenge_set_I, mpz_t sk, VTD_crs_t& crs, mpz_t g_rsa, mpz_t prime, int n, int t, int lambda) {
    
    generate_shares(n, t, sk, prime, w_shares);
    mpz_powm(H, g_rsa, sk, prime);
    
    for(int i = 0; i < n; i++) { // 修复为 0-based
        mpz_powm(H_shares[i], g_rsa, w_shares[i], prime);
        LHP_PGen(Z[i], crs.params, w_shares[i]);
        
        // 【核心修复·已落实】NIZK 将时间锁谜题 Z[i].u、Z[i].v 与公共参数
        // (prime, g_rsa) 一并混入 Fiat-Shamir 挑战的哈希输入，
        // 防止证明在不同声明之间被移植重放。
        ZKprove(proofs[i], prime, g_rsa, w_shares[i], Z[i].u, Z[i].v, lambda);
    }

    // 模拟 Fiat-Shamir 变换生成大小为 t-1 的公开挑战集 I (0 到 n-1 之间不重复的索引)
    // 真实场景下应通过哈希 (H, H_shares, Z, proofs) 生成
    challenge_set_I.clear();
    for(int i = 0; i < t - 1; i++) {
        challenge_set_I.push_back(i); 
    }
}

bool Verify_VTD(VTD_crs_t& crs, LHP_Puzzle* Z, mpz_t H, mpz_t* H_shares, mpz_t* w_shares_revealed, Proof* proofs, const std::vector<int>& challenge_set_I, mpz_t prime, mpz_t g_rsa, int n, int t) {
    
    // 1. 验证挑战集 I 中公开份额的绝对正确性 (不用解时间锁)
    for (int i : challenge_set_I) {
        mpz_t H_check;
        mpz_init(H_check);
        mpz_powm(H_check, g_rsa, w_shares_revealed[i], prime);
        if (mpz_cmp(H_check, H_shares[i]) != 0) {
            std::cerr << "[错误] 公开份额公钥不匹配！索引: " << i << std::endl;
            mpz_clear(H_check);
            return false;
        }
        mpz_clear(H_check);
    }

    // 2. 验证所有份额的 NIZK 和承诺一致性
    for(int i = 0; i < n; i++) {
        if (ZKverify(prime, g_rsa, Z[i].u, Z[i].v, proofs[i]) == 0) {
            std::cerr << "[错误] NIZK 验证失败！索引: " << i << std::endl;
            return false;
        }
        if (mpz_cmp(proofs[i].P, H_shares[i]) != 0) {
            std::cerr << "[错误] 承诺不匹配！索引: " << i << std::endl;
            return false;
        }
    }
    
    // 3. 【核心修复】验证插值一致性 (Interpolation Consistency)
    // 只需要使用公开集 I 和 任意 1 个未公开的份额(如 target_j)，就能验证总体承诺 H
    // 保证满足公式: ( \prod_{i \in I} H_i^{L_i(0)} ) * H_j^{L_j(0)} == H
    
    int target_j = -1;
    for(int i = 0; i < n; i++) {
        if (std::find(challenge_set_I.begin(), challenge_set_I.end(), i) == challenge_set_I.end()) {
            target_j = i; break;
        }
    }

    std::vector<int> point_x_set;
    for (int i : challenge_set_I) point_x_set.push_back(i + 1); // X 坐标是索引 + 1
    point_x_set.push_back(target_j + 1);

    mpz_t H_reconstructed, L_i, temp;
    mpz_inits(H_reconstructed, L_i, temp, NULL);
    mpz_set_ui(H_reconstructed, 1);

    // 插值重构 H
    for (int current_x : point_x_set) {
        int idx = current_x - 1; // 还原为数组索引
        compute_lagrange_basis_at_zero(L_i, current_x, point_x_set, prime);
        
        mpz_powm(temp, H_shares[idx], L_i, prime);
        mpz_mul(H_reconstructed, H_reconstructed, temp);
        mpz_mod(H_reconstructed, H_reconstructed, prime);
    }

    bool isValid = (mpz_cmp(H, H_reconstructed) == 0);
    if (!isValid) {
        std::cerr << "[错误] 插值一致性失败！这说明有恶意的未公开份额！" << std::endl;
    }

    mpz_clears(H_reconstructed, L_i, temp, NULL);
    return isValid;
}