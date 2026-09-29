/* src/benchmark_micro_ops.cpp - UCCDP 微观原语级耗时分析 (包含适配器签名验证) */
#include <stdio.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <map>
#include <string>

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
const int TEST_LOOPS = 50; // 跑 50 次取平均，确保微秒级操作的准确性

// 耗时记录器
map<string, double> time_records;

void record_time(const string& step_name, high_resolution_clock::time_point start, high_resolution_clock::time_point end) {
    double duration_us = duration<double, std::micro>(end - start).count();
    time_records[step_name] += duration_us;
}

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

int main() {
    init_random_state();
    init_curve_env();

    printf("\n========================================================================\n");
    printf(" UCCDP Protocol Micro-Operations Benchmark (N=%d, n=%d, t=%d)\n", LAMBDA_RSA, TEST_N, TEST_T);
    printf("========================================================================\n");
    printf("正在进行高精度计时测试 (循环 %d 次)...\n\n", TEST_LOOPS);

    // 全局实例初始化 (不计入单次流程时间)
    AdaptorSig_Schnorr as_sys; as_sys.setup();
    PSSig ps_sys; ps_sys.setup(); ps_sys.keygen();
    SchnorrSig sch_sys; sch_sys.setup();
    
    mpz_t prime, g_rsa, sk_vtd_dummy;
    mpz_inits(prime, g_rsa, sk_vtd_dummy, NULL);
    generate_prime(prime, LAMBDA_RSA);
    mpz_urandomm(g_rsa, grnd_state, prime);
    mpz_urandomb(sk_vtd_dummy, grnd_state, LAMBDA_RSA);

    vector<LHP_Puzzle> Z_pool(TEST_N + 1);
    vector<Proof> proofs_pool(TEST_N + 1);
    mpz_t w_s[TEST_N + 1], H_s[TEST_N + 1];
    for(int i=0; i<=TEST_N; i++) mpz_inits(w_s[i], H_s[i], NULL);
    mpz_t H_vtd; mpz_init(H_vtd);

     VTD_crs_t crs; 
    auto t_setup_start = high_resolution_clock::now();
    Setup_VTD(crs, LAMBDA_RSA, 10000);
    auto t_setup_end = high_resolution_clock::now();
    // 手动记录这唯一的一次极度耗时操作
    time_records["0.00_VTD_System_Setup(Once)"] = duration<double, std::micro>(t_setup_end - t_setup_start).count() * TEST_LOOPS; // 乘以 TEST_LOOPS 是为了抵消后面打印时的除法

    for (int loop = 0; loop < TEST_LOOPS; loop++) {
        
       
        // --- 2. 密钥与秘密生成 ---
        Fr sk_A; G1Point pk_A;
        auto t1 = high_resolution_clock::now();
        as_sys.keygen(sk_A, pk_A);
        auto t2 = high_resolution_clock::now();
        record_time("1.02_ECC_KeyGen", t1, t2);

        Fr y; G1Point Y;
        t1 = high_resolution_clock::now();
        as_sys.gen_secret_pair(y, Y);
        t2 = high_resolution_clock::now();
        record_time("1.03_Gen_Witness_y", t1, t2);

        // --- 3. 盲签名交互 ---
        Fr tid, t_blind; tid.setByCSPRNG(); t_blind.setByCSPRNG();
        G1Point com, sig1_p, sig2_p, sig1, sig2;
        
        t1 = high_resolution_clock::now();
        ps_sys.commit(com, tid, t_blind);
        t2 = high_resolution_clock::now();
        record_time("2.01_PS_Commit(Alice)", t1, t2);

        t1 = high_resolution_clock::now();
        ps_sys.sign(sig1_p, sig2_p, com);
        t2 = high_resolution_clock::now();
        record_time("2.02_PS_BlindSign(Carol)", t1, t2);

        t1 = high_resolution_clock::now();
        ps_sys.unblind(sig1, sig2, sig1_p, sig2_p, t_blind);
        t2 = high_resolution_clock::now();
        record_time("2.03_PS_Unblind(Alice)", t1, t2);

        t1 = high_resolution_clock::now();
        ps_sys.verify(tid, sig1, sig2);
        t2 = high_resolution_clock::now();
        record_time("2.04_PS_Verify(Carol)", t1, t2);

        // --- 4. 承诺随机化 (防作恶) ---
        Fr r; r.setByCSPRNG(); G1Point Y_prime, R_rand;
        t1 = high_resolution_clock::now();
        G1Point::mul(R_rand, as_sys.g, r);
        G1Point::add(Y_prime, Y, R_rand);
        t2 = high_resolution_clock::now();
        record_time("2.05_Randomize_Commitment(Y')", t1, t2);

        // --- 5. 适配器签名 (生成与验证) ---
        Fr s_pre_A; G1Point R_pre_A;
        
        // 5.1 生成预签名
        t1 = high_resolution_clock::now();
        as_sys.pre_sign(s_pre_A, R_pre_A, sk_A, "TX_PRE", Y);
        t2 = high_resolution_clock::now();
        record_time("2.06_Adaptor_PreSign", t1, t2);

        // 5.2 验证预签名 (新增加的步骤)
        t1 = high_resolution_clock::now();
        bool is_valid = as_sys.pre_verify(pk_A, s_pre_A, R_pre_A, "TX_PRE", Y);
        t2 = high_resolution_clock::now();
        record_time("2.07_Adaptor_PreVerify", t1, t2);
        if (!is_valid) { cerr << "Warning: PreVerify failed!" << endl; }


        // --- 7. 退款与提取 (极速原语) ---
        Fr s_full_A;
        t1 = high_resolution_clock::now();
        as_sys.adapt(s_full_A, s_pre_A, y);
        t2 = high_resolution_clock::now();
        record_time("3.01_Adaptor_Adapt(Alice)", t1, t2);

        Fr y_extracted;
        t1 = high_resolution_clock::now();
        as_sys.extract(y_extracted, s_full_A, s_pre_A);
        t2 = high_resolution_clock::now();
        record_time("3.02_Adaptor_Extract(Carol)", t1, t2);

    
    }

    // --- 打印格式化结果 ---
    printf("| %-40s | %-12s | %-12s |\n", "Micro-Operation Step", "Time (us)", "Time (ms)");
    printf("|------------------------------------------|--------------|--------------|\n");
    for (auto const& [name, total_us] : time_records) {
        double avg_us = total_us / TEST_LOOPS;
        double avg_ms = avg_us / 1000.0;
        printf("| %-40s | %-12.2f | %-12.4f |\n", name.c_str(), avg_us, avg_ms);
    }
    printf("========================================================================\n");

    // 全局清理
    mpz_clears(prime, g_rsa, H_vtd, sk_vtd_dummy, NULL);
    for(int i=0; i<=TEST_N; i++) mpz_clears(w_s[i], H_s[i], NULL);

    return 0;
}