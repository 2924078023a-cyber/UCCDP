/* src/benchmark_phases.cpp - 修复了 FPE 崩溃的安全版 */
#include <stdio.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <cstdlib> // 用于 exit()

#include "vtd.h"
#include "lhp.h"
#include "nizk.h"
#include "util.h"
#include "Shamir.h"
#include "adaptor_sig.h"
#include "ps_sig.h"
#include "schnorr.h"

#include <gmp.h>
#include <openssl/rand.h>

using namespace std;
using namespace std::chrono;

const int TEST_N = 64; 
const int TEST_T = 32;
const int LAMBDA_RSA = 3072;
const int TEST_LOOPS = 20;

gmp_randstate_t grnd_state;
void init_random_state() {
    gmp_randinit_default(grnd_state);
    unsigned long seed = 0;
    FILE *fp = fopen("/dev/urandom", "r");
    if (fp) {
        if (fread(&seed, sizeof(seed), 1, fp) != 1) seed = 0;
        fclose(fp);
    }
    if (seed == 0) { RAND_bytes((unsigned char*)&seed, sizeof(seed)); }
    gmp_randseed_ui(grnd_state, seed);
}

// 辅助检测函数：防止 generate_prime 生成了空值导致 FPE
void assert_prime_valid(mpz_t p, const char* name) {
    if (mpz_cmp_ui(p, 0) == 0) {
        fprintf(stderr, "\n[致命错误] %s 等于 0！请检查 util.cpp 中的素数生成函数是否正确实现！\n", name);
        exit(1);
    }
}

int main() {
    init_random_state();
    init_curve_env();

    printf("\n========================================================================\n");
    printf(" UCCDP Protocol 4-Phase Overhead (N=%d, n=%d, t=%d) [Excluding Solve]\n", LAMBDA_RSA, TEST_N, TEST_T);
    printf("========================================================================\n");
    printf("正在预热环境和分配内存，请稍候...\n");

    // --- 全局实例准备 ---
    AdaptorSig_Schnorr as_sys; as_sys.setup();
    PSSig ps_sys; ps_sys.setup(); ps_sys.keygen();
    SchnorrSig sch_sys; sch_sys.setup();
    
    VTD_crs_t crs; 
    Setup_VTD(crs, LAMBDA_RSA, 10000); 

    mpz_t prime, g_rsa;
    mpz_inits(prime, g_rsa, NULL);
    generate_prime(prime, LAMBDA_RSA);
    
    // 【防御点 1】：确保 prime 不为 0，否则后续所有 mpz_mod 和 powm 都会触发 FPE
    assert_prime_valid(prime, "总域参数 prime");
    mpz_urandomm(g_rsa, grnd_state, prime);

    // 【防御点 2】：弃用 std::vector，改用原始数组，彻底避免 GMP 的 Rule of Three 内存析构破坏
    LHP_Puzzle Z_pool[TEST_N];
    Proof proofs_pool[TEST_N];
    
    mpz_t w_s[TEST_N], H_s[TEST_N];
    for(int i=0; i<TEST_N; i++) mpz_inits(w_s[i], H_s[i], NULL);
    mpz_t H_vtd, sk_vtd_dummy;
    mpz_inits(H_vtd, sk_vtd_dummy, NULL);

    double time_phase1 = 0, time_phase2 = 0, time_phase3 = 0, time_phase4 = 0;

    for (int loop = 0; loop < TEST_LOOPS; loop++) {
        // ... (Phase 1 逻辑不变) ...
        auto t_start = high_resolution_clock::now();
        Fr sk_A, sk_C, sk_B; G1Point pk_A, pk_C, pk_B;
        as_sys.keygen(sk_A, pk_A);
        as_sys.keygen(sk_C, pk_C);
        as_sys.keygen(sk_B, pk_B);
        mpz_urandomb(sk_vtd_dummy, grnd_state, LAMBDA_RSA);

        Fr y; G1Point Y;
        as_sys.gen_secret_pair(y, Y);

        auto t_end = high_resolution_clock::now();
        time_phase1 += duration<double, milli>(t_end - t_start).count();

        // ==========================================
        // Phase 2: 资产锁定阶段
        // ==========================================
        t_start = high_resolution_clock::now();
        
        Fr tid, t_blind; tid.setByCSPRNG(); t_blind.setByCSPRNG();
        G1Point com, sig1_p, sig2_p, sig1, sig2;
        ps_sys.commit(com, tid, t_blind);
        ps_sys.sign(sig1_p, sig2_p, com);
        ps_sys.unblind(sig1, sig2, sig1_p, sig2_p, t_blind);

        Fr s_pre_A; G1Point R_pre_A;
        as_sys.pre_sign(s_pre_A, R_pre_A, sk_C, "TX_PRE", Y);
        
        std::vector<int> challenge_set_1, challenge_set_2, challenge_set_3;

        // 注意：将 Z_pool.data() 改为直接传入数组指针 Z_pool
        Commit_VTD(Z_pool, proofs_pool, H_vtd, w_s, H_s, challenge_set_1, sk_vtd_dummy, crs, g_rsa, prime, TEST_N, TEST_T, LAMBDA_RSA);
        Verify_VTD(crs, Z_pool, H_vtd, H_s, w_s, proofs_pool, challenge_set_1, prime, g_rsa, TEST_N, TEST_T);

        Commit_VTD(Z_pool, proofs_pool, H_vtd, w_s, H_s, challenge_set_2, sk_vtd_dummy, crs, g_rsa, prime, TEST_N, TEST_T, LAMBDA_RSA);
        Verify_VTD(crs, Z_pool, H_vtd, H_s, w_s, proofs_pool, challenge_set_2, prime, g_rsa, TEST_N, TEST_T);

        ps_sys.verify(tid, sig1, sig2);
        
        Fr r; r.setByCSPRNG();
        G1Point Y_prime, R_rand;
        G1Point::mul(R_rand, as_sys.g, r);
        G1Point::add(Y_prime, Y, R_rand);

        Fr s_pre_C; G1Point R_pre_C;
        as_sys.pre_sign(s_pre_C, R_pre_C, sk_B, "TX_B1", Y_prime);

        Commit_VTD(Z_pool, proofs_pool, H_vtd, w_s, H_s, challenge_set_3, sk_vtd_dummy, crs, g_rsa, prime, TEST_N, TEST_T, LAMBDA_RSA);
        Verify_VTD(crs, Z_pool, H_vtd, H_s, w_s, proofs_pool, challenge_set_3, prime, g_rsa, TEST_N, TEST_T);
        
        t_end = high_resolution_clock::now();
        time_phase2 += duration<double, milli>(t_end - t_start).count();

        // ... (Phase 3 逻辑不变) ...
        t_start = high_resolution_clock::now();
        Fr s_full_A; as_sys.adapt(s_full_A, s_pre_A, y);
        Fr y_extracted; as_sys.extract(y_extracted, s_full_A, s_pre_A);
        Fr y_prime; Fr::add(y_prime, y_extracted, r);
        Fr s_full_C; as_sys.adapt(s_full_C, s_pre_C, y_prime);
        t_end = high_resolution_clock::now();
        time_phase3 += duration<double, milli>(t_end - t_start).count();

        // ==========================================
        // Phase 4: 转账完成阶段 
        // ==========================================
        t_start = high_resolution_clock::now();
        
        std::vector<int> x_points;
        mpz_t y_shares[TEST_T];
        for(int i = 0; i < TEST_T; i++) {
            x_points.push_back(i + 1); 
            mpz_init_set(y_shares[i], w_s[i]); 
        }
        
        mpz_t recovered_sk; mpz_init(recovered_sk);

        // 【修复】原来这里连续调用了 3 次 recover_secret（复制粘贴残留），
        // 导致 Phase 4 计时被放大约 3 倍。协议中只需重构一次秘密。
        recover_secret(TEST_T, x_points, y_shares, prime, recovered_sk);

        SchnorrSignature final_sig;
        sch_sys.sign(final_sig, sk_C, "TX_FINAL_CLAIM");

        t_end = high_resolution_clock::now();
        time_phase4 += duration<double, milli>(t_end - t_start).count();

        for(int i = 0; i < TEST_T; i++) mpz_clear(y_shares[i]);
        mpz_clear(recovered_sk);
    }

    // 打印结果
    printf("| %-30s | %-15s |\n", "UCCDP Protocol Phase", "Time (ms)");
    printf("|--------------------------------|-----------------|\n");
    printf("| Phase 1: System Setup          | %-15.3f |\n", time_phase1 / TEST_LOOPS);
    printf("| Phase 2: Asset Locking (B0+B1) | %-15.3f |\n", time_phase2 / TEST_LOOPS);
    printf("| Phase 3: Asset Refund (Active) | %-15.3f |\n", time_phase3 / TEST_LOOPS);
    printf("| Phase 4: Transfer Complete     | %-15.3f |\n", time_phase4 / TEST_LOOPS);
    printf("========================================================================\n");

    mpz_clears(prime, g_rsa, H_vtd, sk_vtd_dummy, NULL);
    for(int i=0; i<TEST_N; i++) mpz_clears(w_s[i], H_s[i], NULL);

    return 0;
}