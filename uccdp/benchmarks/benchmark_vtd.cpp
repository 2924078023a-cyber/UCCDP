/* benchmark_vtd.cpp - 针对 Table IV 优化的安全实验版本 */
#include <stdio.h>
#include <iostream>
#include <vector>
#include <algorithm> // 必须包含，用于挑战集的 std::find
#include <chrono>
#include <iomanip>
#include <cmath>

#include "vtd.h"
#include "lhp.h"
#include "nizk.h"
#include "util.h"
#include "Shamir.h"

#include <gmp.h>
#include <openssl/rand.h>

using namespace std;
using namespace std::chrono;

const int MAX_N = 200; 
const int VERIFY_LOOPS = 5; 

// 全局随机状态
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

void run_test_suite(int lambda, unsigned long long T_val, const vector<int>& n_cases) {
    VTD_crs_t crs;
    printf("\n[Setup] 正在生成参数 (N=%d bits, T=%llu)... \n", lambda, T_val);
    Setup_VTD(crs, lambda, T_val);

    mpz_t sk_shared, prime, g_rsa;
    mpz_inits(sk_shared, prime, g_rsa, NULL);
    
    // 【修复 1】彻底弃用 util.cpp 的素数生成，原生保证防崩溃
    mpz_urandomb(prime, grnd_state, lambda);
    mpz_setbit(prime, lambda - 1); // 保证最高位为1，确保位长
    mpz_nextprime(prime, prime);
    
    mpz_urandomm(g_rsa, grnd_state, prime);
    mpz_urandomb(sk_shared, grnd_state, lambda);

    // 【修复 2】预分配内存池改为 0-based indexing，防止越界
    vector<LHP_Puzzle> Z_pool(MAX_N);
    vector<Proof> proofs_pool(MAX_N);
    mpz_t w_s_pool[MAX_N], H_s_pool[MAX_N];
    for(int i = 0; i < MAX_N; i++) mpz_inits(w_s_pool[i], H_s_pool[i], NULL);
    mpz_t H_vtd; mpz_init(H_vtd);

    printf("=========================================================================================\n");
    printf(" TABLE IV: Performance Analysis (N=%d, T=%llu)\n", lambda, T_val);
    printf("=========================================================================================\n");
    printf("| %-4s | %-4s | %-15s | %-15s | %-15s |\n", "n", "t", "Commit (ms)", "Verify (ms)", "Solve (1)(ms)");
    printf("|------|------|-----------------|-----------------|-----------------|\n");

    for (int n : n_cases) {
        int t = (n + 1) / 2; // t = ceil(n/2)

        // 【新增】用来接收 Commit 生成的挑战集
        std::vector<int> challenge_set;

        // 1. Commit 测量 (循环取平均)
        int COMMIT_LOOPS = 10;
        auto s1 = high_resolution_clock::now();
        for(int k = 0; k < COMMIT_LOOPS; k++) {
            // 【修复 3】传入 challenge_set
            Commit_VTD(Z_pool.data(), proofs_pool.data(), H_vtd, w_s_pool, H_s_pool, 
                       challenge_set, sk_shared, crs, g_rsa, prime, n, t, lambda);
        }
        auto e1 = high_resolution_clock::now();
        double t_com = duration<double, milli>(e1 - s1).count() / COMMIT_LOOPS;

        // 2. Verify 测量 (取平均值)
        auto s2 = high_resolution_clock::now();
        for(int k = 0; k < VERIFY_LOOPS; k++) {
            // 【修复 3】传入 challenge_set 进行校验
            Verify_VTD(crs, Z_pool.data(), H_vtd, H_s_pool, w_s_pool, proofs_pool.data(), 
                       challenge_set, prime, g_rsa, n, t);
        }
        auto e2 = high_resolution_clock::now();
        double t_vfy = duration<double, milli>(e2 - s2).count() / VERIFY_LOOPS;

        // 3. 【修复 4】补充缺失的 Solve 测量
        // 由于 Solve 是纯连续平方，受 T 影响极大，解开 1 个谜题就代表了协议的物理时间延迟
        mpz_t recovered_s; mpz_init(recovered_s);
        auto s3 = high_resolution_clock::now();

        // 破解第 1 个谜题即可体现开销
        LHP_PSolve(recovered_s, crs.params, Z_pool[0]);

        auto e3 = high_resolution_clock::now();
        double t_sol = duration<double, milli>(e3 - s3).count();

        // 【新增】Solve 正确性校验：LHP 的消息空间是 Z_N，
        // Solve 恢复出的是 s mod N 而非 s 本身，故与 w_s[0] mod N 比较
        {
            mpz_t expected_s; mpz_init(expected_s);
            mpz_mod(expected_s, w_s_pool[0], crs.params.N);
            if (mpz_cmp(recovered_s, expected_s) != 0) {
                fprintf(stderr, "[警告] n=%d: Solve 恢复值 != w mod N，LHP 实现可能存在错误！\n", n);
            }
            mpz_clear(expected_s);
        }
        mpz_clear(recovered_s);

        // 打印单行数据
        printf("| %-4d | %-4d | %-15.3f | %-15.3f | %-15.3f |\n", n, t, t_com, t_vfy, t_sol);
    }
    printf("=========================================================================================\n");

    // 清理
    mpz_clears(sk_shared, prime, g_rsa, H_vtd, NULL);
    for(int i = 0; i < MAX_N; i++) mpz_clears(w_s_pool[i], H_s_pool[i], NULL);
}

int main() {
    init_random_state();
    
    // 自变量集合
    vector<int> n_values = {1, 10, 32, 64, 100};
    
    // 运行两组 T 数据
    run_test_suite(3072, 10000, n_values);   // T = 10^4
    run_test_suite(3072, 10000000, n_values); // T = 10^7 (10^7 次平方，需耗费一定时间)

    return 0;
}