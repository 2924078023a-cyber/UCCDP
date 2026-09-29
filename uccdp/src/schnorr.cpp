/* src/schnorr.cpp */
#include "schnorr.h"
#include "util.h" // 用于通讯统计
#include <openssl/sha.h>
#include <sstream>

using namespace std;

SchnorrSig::SchnorrSig() {
    init_curve_env(); // 确保 MCL 已初始化
}

SchnorrSig::~SchnorrSig() {}

void SchnorrSig::setup() {
    // 设置生成元 g，使用 HashToG1 确保安全，或者直接用标准生成元
    // 这里为了简单，映射一个字符串到 G1
    hashAndMapToG1(g, "schnorr_generator");
}

void SchnorrSig::keygen(Fr& sk, G1Point& pk) {
    sk.setByCSPRNG(); // 密码学安全随机数
    G1Point::mul(pk, g, sk); // pk = sk * g
}

// 内部辅助: 计算哈希 c = H(R, pk, msg)
void compute_schnorr_hash(Fr& c, const G1Point& R, const G1Point& pk, const string& msg) {
    // 拼接 R, pk, msg
    stringstream ss;
    ss << R.getStr(16) << pk.getStr(16) << msg; 
    string raw = ss.str();
    
    // 映射到标量域 Fr
    c.setHashOf(raw.c_str(), raw.length());
}

void SchnorrSig::sign(SchnorrSignature& sig, const Fr& sk, const string& msg) {
    Fr r, c;
    
    // 1. r <- random
    r.setByCSPRNG();
    
    // 2. R = r * g
    G1Point::mul(sig.R, g, r);

    // 3. 计算 pk 用于哈希 (pk = sk * g)
    G1Point pk;
    G1Point::mul(pk, g, sk);

    // 4. c = H(R, pk, msg)
    compute_schnorr_hash(c, sig.R, pk, msg);

    // 5. s = r + c * sk
    Fr temp;
    Fr::mul(temp, c, sk); // temp = c * sk
    Fr::add(sig.s, r, temp); // s = r + temp

    // [统计] 记录签名大小
    g_comm_profiler.log("Schnorr Sig (Generated)", sig.get_size_bytes());
}

bool SchnorrSig::verify(const G1Point& pk, const SchnorrSignature& sig, const string& msg) {
    // 验证: s * g == R + c * pk
    
    G1Point lhs, rhs, temp;
    Fr c;

    // LHS = s * g
    G1Point::mul(lhs, g, sig.s);

    // RHS = R + c * pk
    compute_schnorr_hash(c, sig.R, pk, msg);
    G1Point::mul(temp, pk, c);
    G1Point::add(rhs, sig.R, temp);

    return (lhs == rhs);
}