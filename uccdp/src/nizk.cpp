/* src/nizk.cpp - 真实大数开销重构版 */
#include "nizk.h"
#include "util.h"
#include <string>
#include <functional>

Proof::Proof() {
    mpz_inits(P, R, S, NULL);
}
Proof::~Proof() {
    mpz_clears(P, R, S, NULL);
}

void ZKSetup(uint64_t lambda, mpz_t& crs_range) {
    generate_strong_prime(crs_range, lambda);
}

// 【安全修复】Fiat-Shamir 挑战必须绑定完整声明 (crs_range, z, 谜题 u, v)
// 以及承诺值 (P, R)。旧实现只对 (P, R) 哈希：两个不同声明下只要
// (P, R) 相同就得到相同挑战，证明可以被移植/重放到其他声明上使用，
// 这不是安全的 NIZK。现在把公共参数、生成元、时间锁谜题全部混入哈希。
static void compute_challenge(mpz_t c, mpz_t crs_range, mpz_t z,
                               mpz_t puzzle_u, mpz_t puzzle_v,
                               mpz_t P, mpz_t R) {
    char* crs_str = mpz_get_str(NULL, 16, crs_range);
    char* z_str   = mpz_get_str(NULL, 16, z);
    char* u_str   = mpz_get_str(NULL, 16, puzzle_u);
    char* v_str   = mpz_get_str(NULL, 16, puzzle_v);
    char* p_str   = mpz_get_str(NULL, 16, P);
    char* r_str   = mpz_get_str(NULL, 16, R);

    std::string raw = std::string(crs_str) + "|"
                    + std::string(z_str)   + "|"
                    + std::string(u_str)   + "|"
                    + std::string(v_str)   + "|"
                    + std::string(p_str)   + "|"
                    + std::string(r_str);

    std::hash<std::string> hasher;
    uint64_t h_val = hasher(raw);
    mpz_set_ui(c, h_val);

    free(crs_str); free(z_str); free(u_str);
    free(v_str); free(p_str); free(r_str);
}

void ZKprove(Proof& proof, mpz_t crs_range, mpz_t z, mpz_t w,
             mpz_t puzzle_u, mpz_t puzzle_v, uint64_t lambda) {
    mpz_t r, c;
    mpz_inits(r, c, NULL);

    mpz_powm(proof.P, z, w, crs_range);
    generate_random(r, 256);
    mpz_powm(proof.R, z, r, crs_range);

    compute_challenge(c, crs_range, z, puzzle_u, puzzle_v, proof.P, proof.R);

    mpz_mul(proof.S, c, w);
    mpz_add(proof.S, proof.S, r);

    mpz_clears(r, c, NULL);
}

int ZKverify(mpz_t crs_range, mpz_t z, mpz_t puzzle_u, mpz_t puzzle_v, Proof& proof) {
    mpz_t c, lhs, rhs, temp;
    mpz_inits(c, lhs, rhs, temp, NULL);

    compute_challenge(c, crs_range, z, puzzle_u, puzzle_v, proof.P, proof.R);

    // [核心修复] LHS = z^S mod crs_range (产生真实的验证时间消耗)
    mpz_powm(lhs, z, proof.S, crs_range);

    // RHS = R * P^c mod crs_range
    mpz_powm(temp, proof.P, c, crs_range);
    mpz_mul(rhs, proof.R, temp);
    mpz_mod(rhs, rhs, crs_range);

    int result = (mpz_cmp(lhs, rhs) == 0) ? 1 : 0;

    mpz_clears(c, lhs, rhs, temp, NULL);
    return result;
}
