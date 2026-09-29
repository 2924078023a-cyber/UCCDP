/* src/adaptor_sig.cpp */
#include "adaptor_sig.h"
#include "util.h"
#include <sstream>

using namespace std;

AdaptorSig_Schnorr::AdaptorSig_Schnorr() {
    init_curve_env();
}

AdaptorSig_Schnorr::~AdaptorSig_Schnorr() {}

void AdaptorSig_Schnorr::setup() {
    hashAndMapToG1(g, "schnorr_generator");
}

void AdaptorSig_Schnorr::keygen(Fr& sk, G1Point& pk) {
    sk.setByCSPRNG();
    G1Point::mul(pk, g, sk);
}

void AdaptorSig_Schnorr::gen_secret_pair(Fr& y, G1Point& Y) {
    y.setByCSPRNG();
    G1Point::mul(Y, g, y);
}

void as_compute_hash(Fr& c, const G1Point& R, const G1Point& pk, const string& msg) {
    stringstream ss;
    ss << R.getStr(16) << pk.getStr(16) << msg;
    string raw = ss.str();
    c.setHashOf(raw.c_str(), raw.length());
}

void AdaptorSig_Schnorr::pre_sign(Fr& s_pre, G1Point& R_pre, const Fr& sk, const string& msg, const G1Point& Y) {
    Fr r, c;
    G1Point R;

    r.setByCSPRNG();
    G1Point::mul(R, g, r);
    G1Point::add(R_pre, R, Y);

    G1Point pk;
    G1Point::mul(pk, g, sk);

    as_compute_hash(c, R_pre, pk, msg);

    Fr temp;
    Fr::mul(temp, c, sk);
    Fr::add(s_pre, r, temp);

    // [修改] 使用 get_mcl_size
    g_comm_profiler.log("Adaptor Pre-Sig", get_mcl_size(s_pre) + get_mcl_size(R_pre));
}

bool AdaptorSig_Schnorr::pre_verify(const G1Point& pk, const Fr& s_pre, const G1Point& R_pre, const string& msg, const G1Point& Y) {
    Fr c;
    as_compute_hash(c, R_pre, pk, msg);

    G1Point lhs, rhs, temp;
    G1Point::mul(temp, g, s_pre);
    G1Point::add(lhs, temp, Y);

    G1Point::mul(temp, pk, c);
    G1Point::add(rhs, R_pre, temp);

    return (lhs == rhs);
}

void AdaptorSig_Schnorr::adapt(Fr& s_full, const Fr& s_pre, const Fr& y) {
    Fr::add(s_full, s_pre, y);
    // [修改] 使用 get_mcl_size
    g_comm_profiler.log("Adaptor Full-Sig (Scalar)", get_mcl_size(s_full));
}

void AdaptorSig_Schnorr::extract(Fr& y, const Fr& s_full, const Fr& s_pre) {
    Fr::sub(y, s_full, s_pre);
}