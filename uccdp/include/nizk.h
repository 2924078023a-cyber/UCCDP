/* include/nizk.h */
#ifndef NIZK_H
#define NIZK_H

#include <gmp.h>
#include <stdint.h>

struct Proof {
    mpz_t P; // 注意您的代码里有时叫 P/R/S，有时叫 t/s
    mpz_t R; // 这里统一为您上传的 nizk.cpp 里的风格
    mpz_t S;

    Proof();
    ~Proof();
};

void ZKSetup(uint64_t lambda, mpz_t& crs_range);
// 【签名变更】puzzle_u / puzzle_v 为该证明所对应的时间锁谜题，
// 必须混入 Fiat-Shamir 挑战哈希，防止证明在不同声明间被移植重放
void ZKprove(Proof& proof, mpz_t crs_range, mpz_t z, mpz_t w,
             mpz_t puzzle_u, mpz_t puzzle_v, uint64_t lambda);
int ZKverify(mpz_t crs_range, mpz_t z, mpz_t puzzle_u, mpz_t puzzle_v, Proof& proof);

#endif