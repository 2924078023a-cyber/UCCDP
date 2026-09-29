/* src/ps_sig.cpp */
#include "ps_sig.h"
#include "util.h"

using namespace std;

PSSig::PSSig() {
    init_curve_env();
}

PSSig::~PSSig() {}

void PSSig::setup() {
    hashAndMapToG1(g, "ps_generator_g1");
    hashAndMapToG2(gt_gen, "ps_generator_g2");
}

void PSSig::keygen() {
    x.setByCSPRNG();
    y.setByCSPRNG();

    G2Point::mul(X_tilde, gt_gen, x);
    G2Point::mul(Y_tilde, gt_gen, y);

    G1Point::mul(X_G1, g, x);
    G1Point::mul(Y_G1, g, y);
}

void PSSig::commit(G1Point& com, const Fr& m, const Fr& t) {
    G1Point t_part, m_part;
    
    G1Point::mul(t_part, g, t);
    G1Point::mul(m_part, Y_G1, m);
    
    G1Point::add(com, t_part, m_part);
    
    // [修改] 使用 get_mcl_size
    g_comm_profiler.log("PS Commitment", get_mcl_size(com));
}

void PSSig::sign(G1Point& sigma1, G1Point& sigma2, const G1Point& com) {
    Fr u;
    u.setByCSPRNG();

    G1Point::mul(sigma1, g, u);

    G1Point temp;
    G1Point::add(temp, X_G1, com);
    G1Point::mul(sigma2, temp, u);

    // [修改] 使用 get_mcl_size
    g_comm_profiler.log("PS Blind Sig", get_mcl_size(sigma1) + get_mcl_size(sigma2));
}

void PSSig::unblind(G1Point& sigma1, G1Point& sigma2, 
                    const G1Point& sigma1_prime, const G1Point& sigma2_prime, const Fr& t) {
    sigma1 = sigma1_prime;

    G1Point temp;
    G1Point::mul(temp, sigma1_prime, t);
    G1Point::sub(sigma2, sigma2_prime, temp);
}

bool PSSig::verify(const Fr& m, const G1Point& sigma1, const G1Point& sigma2) {
    G2Point lhs_g2, temp_g2;
    G2Point::mul(temp_g2, Y_tilde, m);
    G2Point::add(lhs_g2, X_tilde, temp_g2);

    Fp12 e1, e2;
    pairing(e1, sigma1, lhs_g2);
    pairing(e2, sigma2, gt_gen);

    return (e1 == e2);
}