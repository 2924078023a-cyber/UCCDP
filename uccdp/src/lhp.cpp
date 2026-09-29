/* src/lhp.cpp - 安全重构版 */
#include "lhp.h"
#include "util.h"
#include <stdio.h>

LHP_param_t::LHP_param_t() { mpz_inits(N, N2, g, h, T, NULL);}
LHP_param_t::~LHP_param_t() {mpz_clears(N, N2, g, h, T, NULL);}
LHP_Puzzle::LHP_Puzzle() {mpz_inits(u, v, NULL);}
LHP_Puzzle::~LHP_Puzzle() { mpz_clears(u, v, NULL);}

void LHP_PSetup(LHP_param_t& params, int lambda, unsigned long T_val) {
    mpz_t p, q, phi_N, phi_N2, p_minus_1, q_minus_1;
    mpz_inits(p, q, phi_N, phi_N2, p_minus_1, q_minus_1, NULL);
    
    mpz_set_ui(params.T, T_val); 

    // 生成强素数 p, q
    generate_strong_prime(p, lambda / 2);
    generate_strong_prime(q, lambda / 2);
    mpz_mul(params.N, p, q);
    mpz_mul(params.N2, params.N, params.N); // N2 = N^2

    // 计算欧拉函数 phi(N) = (p-1)(q-1)
    mpz_sub_ui(p_minus_1, p, 1);
    mpz_sub_ui(q_minus_1, q, 1);
    mpz_mul(phi_N, p_minus_1, q_minus_1);

    // 【必须补上这一行！】计算 phi(N^2) = N * phi(N)
    mpz_mul(phi_N2, params.N, phi_N);

    // 生成 g
    random_group_element(params.g, params.N2);

    // 【核心修复】计算 h = g^(2^T) mod N^2
    mpz_t e, base_two;
    mpz_inits(e, base_two, NULL);
    mpz_set_ui(base_two, 2);
    mpz_powm_ui(e, base_two, T_val, phi_N2); // 降阶必须用 phi(N^2)
    mpz_powm(params.h, params.g, e, params.N2);

    mpz_clears(p, q, phi_N, phi_N2, p_minus_1, q_minus_1, e, base_two, NULL);
}


void LHP_PGen(LHP_Puzzle& Z, LHP_param_t& pp, mpz_t s) {
    mpz_t r, hr, ns;
    mpz_inits(r, hr, ns, NULL);
    generate_random(r, 256);

    // 【核心修复】 u = g^r mod N^2
    mpz_powm(Z.u, pp.g, r, pp.N2);

    // h^r mod N^2
    mpz_powm(hr, pp.h, r, pp.N2); 
    
    // (1+N)^s = 1 + N*s mod N^2
    mpz_mul(ns, pp.N, s);
    mpz_add_ui(ns, ns, 1);
    mpz_mod(ns, ns, pp.N2);

    // v = h^r * (1+N)^s mod N^2
    mpz_mul(Z.v, hr, ns);
    mpz_mod(Z.v, Z.v, pp.N2);

    mpz_clears(r, hr, ns, NULL);
}

void LHP_PSolve(mpz_t s, LHP_param_t& pp, LHP_Puzzle& Z) {
    // 注意：LHP 谜题的消息空间是 Z_N（而非 Z_{N^2}），
    // 因为 (1+N)^s mod N^2 = 1 + N*(s mod N)。
    // 因此本函数返回的是 s mod N；若原始明文 s >= N，
    // 调用方只能恢复出 s mod N（协议中份额/密钥均应取自 Z_N）。
    unsigned long T_val = mpz_get_ui(pp.T);
    mpz_t u_prime, u_inv, part2;
    mpz_init_set(u_prime, Z.u);
    mpz_inits(u_inv, part2, NULL);

    // 连续平方 T 次: u' = u^(2^T) mod N^2 (破解时间锁的核心计算)
    for(unsigned long i = 0; i < T_val; i++) {
        mpz_powm_ui(u_prime, u_prime, 2, pp.N2);
    }

    // 求逆元 u'^-1 mod N^2 
    mpz_invert(u_inv, u_prime, pp.N2);
    
    // (1+N)^s = v * u'^-1 mod N^2
    mpz_mul(part2, Z.v, u_inv);
    mpz_mod(part2, part2, pp.N2);
    
    // s = (part2 - 1) / N
    mpz_sub_ui(s, part2, 1);
    mpz_divexact(s, s, pp.N); // 必须能整除，否则说明难题被篡改

    mpz_clears(u_prime, u_inv, part2, NULL);
}