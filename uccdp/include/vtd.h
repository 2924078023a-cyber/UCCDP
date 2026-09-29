/* include/vtd.h */
#ifndef VTD_H
#define VTD_H

#include <vector>
#include <gmp.h>
#include "lhp.h"
#include "nizk.h"

struct VTD_crs_t {
    LHP_param_t params; // 包含 N, g, h, T
    mpz_t crs_range;

    VTD_crs_t();
    ~VTD_crs_t();
};

void Setup_VTD(VTD_crs_t& crs, int lambda, unsigned long T);
// Commit 会输出挑战集 I (大小为 t-1)，表示直接明文公开的份额索引
void Commit_VTD(LHP_Puzzle* Z, Proof* proofs, mpz_t H, mpz_t* w_shares, mpz_t* H_shares, std::vector<int>& challenge_set_I, mpz_t sk, VTD_crs_t& crs, mpz_t g_rsa, mpz_t prime, int n, int t, int lambda);

// Verify 只利用公开集 I 和公钥 H 验证合法性
bool Verify_VTD(VTD_crs_t& crs, LHP_Puzzle* Z, mpz_t H, mpz_t* H_shares, mpz_t* w_shares_revealed, Proof* proofs, const std::vector<int>& challenge_set_I, mpz_t prime, mpz_t g_rsa, int n, int t);
#endif