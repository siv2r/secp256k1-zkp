/**********************************************************************
 * Copyright (c) 2023 Zhe Pang                                        *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORR_ADAPTOR_TESTS_H
#define SECP256K1_MODULE_SCHNORR_ADAPTOR_TESTS_H

#include "../../../include/secp256k1_schnorrsig.h"
#include "../../../include/secp256k1_schnorr_adaptor.h"

/* Checks that a bit flip in the n_flip-th argument (that has n_bytes many
 * bytes) changes the hash function
 */
static void nonce_function_schnorr_adaptor_bitflip(unsigned char **args, size_t n_flip, size_t n_bytes, size_t algolen) {
    unsigned char nonces[2][32];
    CHECK(nonce_function_schnorr_adaptor(nonces[0], args[0], args[1], args[2], args[3], args[4], algolen, args[5]) == 1);
    secp256k1_testrand_flip(args[n_flip], n_bytes);
    CHECK(nonce_function_schnorr_adaptor(nonces[1], args[0], args[1], args[2], args[3], args[4], algolen, args[5]) == 1);
    CHECK(secp256k1_memcmp_var(nonces[0], nonces[1], 32) != 0);
}

static void run_nonce_function_schnorr_adaptor_tests(void) {
    unsigned char tag[20] = "SchnorrAdaptor/nonce";
    unsigned char aux_tag[18] = "SchnorrAdaptor/aux";
    unsigned char algo[20] = "SchnorrAdaptor/nonce";
    size_t algolen = sizeof(algo);
    secp256k1_sha256 sha;
    secp256k1_sha256 sha_optimized;
    secp256k1_scalar adaptor_scalar;
    secp256k1_gej tj;
    secp256k1_ge tg;
    unsigned char nonce[32], nonce_z[32];
    unsigned char msg[32];
    unsigned char key[32];
    unsigned char t[32];
    unsigned char adaptor33[33];
    unsigned char pk[32];
    unsigned char aux_rand[32];
    unsigned char *args[6];
    int i;
    size_t size = 33;

    /* Check that hash initialized by
     * secp256k1_nonce_function_schnorr_adaptor_sha256_tagged has the expected
     * state. */
    secp256k1_sha256_initialize_tagged(&sha, tag, sizeof(tag));
    secp256k1_nonce_function_schnorr_adaptor_sha256_tagged(&sha_optimized);
    test_sha256_eq(&sha, &sha_optimized);

   /* Check that hash initialized by
    * secp256k1_nonce_function_schnorr_adaptor_sha256_tagged_aux has the expected
    * state. */
    secp256k1_sha256_initialize_tagged(&sha, aux_tag, sizeof(aux_tag));
    secp256k1_nonce_function_schnorr_adaptor_sha256_tagged_aux(&sha_optimized);
    test_sha256_eq(&sha, &sha_optimized);

    secp256k1_testrand256(msg);
    secp256k1_testrand256(key);
    secp256k1_testrand256(t);
    secp256k1_testrand256(pk);
    secp256k1_testrand256(aux_rand);

    secp256k1_scalar_set_b32(&adaptor_scalar, t, NULL);
    secp256k1_ecmult_gen(&CTX->ecmult_gen_ctx, &tj, &adaptor_scalar);
    secp256k1_ge_set_gej(&tg, &tj);
    CHECK(secp256k1_eckey_pubkey_serialize(&tg, adaptor33, &size, 1) == 1);

    /* Check that a bitflip in an argument results in different nonces. */
    args[0] = msg;
    args[1] = key;
    args[2] = adaptor33;
    args[3] = pk;
    args[4] = algo;
    args[5] = aux_rand;
    for (i = 0; i < COUNT; i++) {
        nonce_function_schnorr_adaptor_bitflip(args, 0, 32, algolen);
        nonce_function_schnorr_adaptor_bitflip(args, 1, 32, algolen);
        nonce_function_schnorr_adaptor_bitflip(args, 2, 33, algolen);
        nonce_function_schnorr_adaptor_bitflip(args, 3, 32, algolen);
        /* Flip algo special case "SchnorrAdaptor/nonce" */
        nonce_function_schnorr_adaptor_bitflip(args, 4, algolen, algolen);
        /* Flip algo again */
        nonce_function_schnorr_adaptor_bitflip(args, 4, algolen, algolen);
        nonce_function_schnorr_adaptor_bitflip(args, 5, 32, algolen);
    }

    /* NULL algo is disallowed */
    CHECK(nonce_function_schnorr_adaptor(nonce, msg, key, t, pk, NULL, 0, NULL) == 0);
    CHECK(nonce_function_schnorr_adaptor(nonce, msg, key, t, pk, algo, algolen, NULL) == 1);
    /* Other algo is fine */
    secp256k1_testrand_bytes_test(algo, algolen);
    CHECK(nonce_function_schnorr_adaptor(nonce, msg, key, t, pk, algo, algolen, NULL) == 1);

    for (i = 0; i < COUNT; i++) {
        unsigned char nonce2[32];
        size_t algolen_tmp;

        /* Different algolen gives different nonce */
        uint32_t offset = secp256k1_testrand_int(algolen - 1);
        algolen_tmp = (algolen + offset) % algolen;
        CHECK(nonce_function_schnorr_adaptor(nonce2, msg, key, t, pk, algo, algolen_tmp, NULL) == 1);
        CHECK(secp256k1_memcmp_var(nonce, nonce2, 32) != 0);
    }

    /* NULL aux_rand argument is allowed, and identical to passing all zero aux_rand. */
    memset(aux_rand, 0, 32);
    CHECK(nonce_function_schnorr_adaptor(nonce_z, msg, key, t, pk, algo, algolen, &aux_rand) == 1);
    CHECK(nonce_function_schnorr_adaptor(nonce, msg, key, t, pk, algo, algolen, NULL) == 1);
    CHECK(secp256k1_memcmp_var(nonce_z, nonce, 32) == 0);
}

static void test_schnorr_adaptor_api(void) {
    unsigned char sk[32];
    unsigned char msg[32];
    unsigned char secadaptor[32];
    unsigned char adaptor33[33] = {
        0x02, 0xC6, 0x04, 0x7F, 0x94, 0x41, 0xED, 0x7D,
        0x6D, 0x30, 0x45, 0x40, 0x6E, 0x95, 0xC0, 0x7C,
        0xD8, 0x5C, 0x77, 0x8E, 0x4B, 0x8C, 0xEF, 0x3C,
        0xA7, 0xAB, 0xAC, 0x09, 0xB9, 0x5C, 0x70, 0x9E, 0xE5
    };
    secp256k1_keypair keypair;
    secp256k1_keypair invalid_keypair = {{ 0 }};
    secp256k1_xonly_pubkey pk;
    secp256k1_xonly_pubkey zero_pk;
    unsigned char sig[65];
    unsigned char sig64[64];
    secp256k1_pubkey t;
    secp256k1_pubkey t2;
    unsigned char extracted_secadaptor[32];

    /** setup **/

    secp256k1_testrand256(sk);
    secp256k1_testrand256(msg);
    secp256k1_testrand256(secadaptor);
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
    CHECK(secp256k1_keypair_xonly_pub(CTX, &pk, NULL, &keypair) == 1);
    memset(&zero_pk, 0, sizeof(zero_pk));
    secp256k1_ec_pubkey_parse(CTX, &t, adaptor33, 33);

    /** main test body **/
    CHECK_ILLEGAL(STATIC_CTX, secp256k1_schnorr_adaptor_presign(STATIC_CTX, sig, msg, &keypair, &t, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_schnorr_adaptor_presign(CTX, NULL, msg, &keypair, &t, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_schnorr_adaptor_presign(CTX, sig, NULL, &keypair, &t, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_schnorr_adaptor_presign(CTX, sig, msg, NULL, &t, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_schnorr_adaptor_presign(CTX, sig, msg, &keypair, NULL, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_schnorr_adaptor_presign(CTX, sig, msg, &invalid_keypair, &t, NULL));

    CHECK(secp256k1_schnorr_adaptor_presign(CTX, sig, msg, &keypair, &t, NULL) == 1);
    CHECK(secp256k1_schnorr_adaptor_extract(CTX, &t2, sig, msg, &pk) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_schnorr_adaptor_extract(CTX, NULL, sig, msg, &pk));
    CHECK_ILLEGAL(CTX, secp256k1_schnorr_adaptor_extract(CTX, &t2, NULL, msg, &pk));
    CHECK_ILLEGAL(CTX, secp256k1_schnorr_adaptor_extract(CTX, &t2, sig, NULL, &pk));
    CHECK_ILLEGAL(CTX, secp256k1_schnorr_adaptor_extract(CTX, &t2, sig, msg, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_schnorr_adaptor_extract(CTX, &t2, sig, msg, &zero_pk));

    CHECK(secp256k1_schnorr_adaptor_adapt(CTX, sig64, sig, secadaptor) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_schnorr_adaptor_adapt(CTX, NULL, sig, secadaptor));
    CHECK_ILLEGAL(CTX, secp256k1_schnorr_adaptor_adapt(CTX, sig64, NULL, secadaptor));
    CHECK_ILLEGAL(CTX, secp256k1_schnorr_adaptor_adapt(CTX, sig64, sig, NULL));

    CHECK(secp256k1_schnorr_adaptor_adapt(CTX, sig64, sig, secadaptor) == 1);
    CHECK(secp256k1_schnorr_adaptor_extract_sec(CTX, extracted_secadaptor, sig, sig64) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_schnorr_adaptor_extract_sec(CTX, NULL, sig, sig64));
    CHECK_ILLEGAL(CTX, secp256k1_schnorr_adaptor_extract_sec(CTX, extracted_secadaptor, NULL, sig64));
    CHECK_ILLEGAL(CTX, secp256k1_schnorr_adaptor_extract_sec(CTX, extracted_secadaptor, sig, NULL));

}

/* Helper function for schnorr_adaptor_vectors
 * Signs the message and checks that it's the same as expected_presig. */
static void test_schnorr_adaptor_spec_vectors_check_presigning(const unsigned char *sk, const unsigned char *pk_serialized, const unsigned char *aux_rand, const unsigned char *msg32, const unsigned char *adaptor_serialized, const unsigned char *expected_presig) {
    unsigned char pre_sig[65];
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey pk, pk_expected;
    secp256k1_pubkey adaptor, adaptor_extracted;
    secp256k1_ec_pubkey_parse(CTX, &adaptor, adaptor_serialized, 33);

    CHECK(secp256k1_keypair_create(CTX, &keypair, sk));
    CHECK(secp256k1_schnorr_adaptor_presign(CTX, pre_sig, msg32, &keypair, &adaptor, aux_rand));
    CHECK(secp256k1_memcmp_var(pre_sig, expected_presig, 65) == 0);

    CHECK(secp256k1_xonly_pubkey_parse(CTX, &pk_expected, pk_serialized));
    CHECK(secp256k1_keypair_xonly_pub(CTX, &pk, NULL, &keypair));
    CHECK(secp256k1_memcmp_var(&pk, &pk_expected, sizeof(pk)) == 0);
    CHECK(secp256k1_schnorr_adaptor_extract(CTX, &adaptor_extracted, pre_sig, msg32, &pk));
    CHECK(secp256k1_ec_pubkey_cmp(CTX, &adaptor_extracted, &adaptor) == 0);
}

/* Helper function for schnorr_adaptor_vectors
 * Extracts the adaptor point and checks if it returns the same value as expected. */
static void test_schnorr_adaptor_spec_vectors_check_extract(const unsigned char *pk_serialized, const unsigned char *msg32, const unsigned char *adaptor_serialized, const unsigned char *pre_sig, int expected) {
    secp256k1_xonly_pubkey pk;
    secp256k1_pubkey adaptor, adaptor_extracted;
    size_t size = 33;
    int cmp_res;

    CHECK(secp256k1_xonly_pubkey_parse(CTX, &pk, pk_serialized));
    CHECK(secp256k1_ec_pubkey_parse(CTX, &adaptor, adaptor_serialized, &size));
    CHECK(secp256k1_schnorr_adaptor_extract(CTX, &adaptor_extracted, pre_sig, msg32, &pk));

    CHECK(expected == (secp256k1_ec_pubkey_cmp(CTX, &adaptor_extracted, &adaptor) == 0));
 }

/* Helper function for schnorr_adaptor_vectors
 * Adapts a Schnorr pre-signature in a BIP340 signature
 * and checks if it is [1] same as expected_sig64, and
 * [2] valid BIP340 signature. */
static void test_schnorr_adaptor_spec_vectors_check_adapt(const unsigned char *pk_serialized, const unsigned char *msg32, unsigned char *pre_sig, const unsigned char *secadaptor, const unsigned char *expected_sig, int expected) {
    unsigned char sig[64];
    secp256k1_xonly_pubkey pk;

    CHECK(secp256k1_schnorr_adaptor_adapt(CTX, sig, pre_sig, secadaptor));
    CHECK(expected == (secp256k1_memcmp_var(sig, expected_sig, 64) == 0));

    CHECK(secp256k1_xonly_pubkey_parse(CTX, &pk, pk_serialized));
    CHECK(secp256k1_schnorrsig_verify(CTX, sig, msg32, 32, &pk));
}

/* Helper function for schnorr_adaptor_vectors
 * Extracts the secret adaptor from a pre-signature and a BIP340
  * signature and checks if it is the same as expected_secadaptor. */
static void test_schnorr_adaptor_spec_vectors_check_extract_sec(const unsigned char *pre_sig, const unsigned char *sig, const unsigned char *expected_secadaptor, int expected) {
    unsigned char sec_adaptor[32];

    CHECK(secp256k1_schnorr_adaptor_extract_sec(CTX, sec_adaptor, pre_sig, sig));
    CHECK(expected == (secp256k1_memcmp_var(sec_adaptor, expected_secadaptor, 32) == 0));
}

/* Test vectors according to Schnorr adaptor signature spec.
 * See https://github.com/ZhePang/Python_Specification_for_Schnorr_Adaptor */
static void test_schnorr_adaptor_vectors(void) {
    {
        /* Presig: Test vector 0 */
        const unsigned char sk[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
        };
        const unsigned char pk[32] = {
            0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10,
            0x49, 0x34, 0x4F, 0x85, 0xF8, 0x9D, 0x52, 0x29,
            0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0,
            0x86, 0x01, 0xF1, 0x13, 0xBC, 0xE0, 0x36, 0xF9
        };
        unsigned char aux_rand[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        const unsigned char msg[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        const unsigned char adaptor[33] = {
            0x02, 0xC6, 0x04, 0x7F, 0x94, 0x41, 0xED, 0x7D,
            0x6D, 0x30, 0x45, 0x40, 0x6E, 0x95, 0xC0, 0x7C,
            0xD8, 0x5C, 0x77, 0x8E, 0x4B, 0x8C, 0xEF, 0x3C,
            0xA7, 0xAB, 0xAC, 0x09, 0xB9, 0x5C, 0x70, 0x9E, 0xE5
        };
        const unsigned char pre_sig[65] = {
            0x03, 0x61, 0x79, 0xDB, 0xF3, 0xE1, 0x32, 0x07,
            0x85, 0x3F, 0x88, 0x0C, 0x7A, 0x7A, 0x85, 0xEC,
            0x67, 0x8B, 0xAD, 0x64, 0xB8, 0x97, 0xF1, 0x08,
            0xD4, 0x76, 0x43, 0x8A, 0xC4, 0xA9, 0x32, 0xEE,
            0x94, 0x97, 0xCC, 0x73, 0xB8, 0xC3, 0x51, 0xF1,
            0x89, 0xB9, 0xD4, 0xFD, 0xE8, 0x93, 0xE3, 0x82,
            0x0D, 0x4B, 0xFF, 0x7F, 0x49, 0xD4, 0xBE, 0x1F,
            0x8B, 0x02, 0xCB, 0x80, 0x8C, 0xD3, 0x19, 0x23, 0xA0
        };
        test_schnorr_adaptor_spec_vectors_check_presigning(sk, pk, aux_rand, msg, adaptor, pre_sig);
        test_schnorr_adaptor_spec_vectors_check_extract(pk, msg, adaptor, pre_sig, 1);
    };
    {
        /* Presig: Test vector 1 */
        const unsigned char sk[32] = {
            0x0B, 0x43, 0x2B, 0x26, 0x77, 0x93, 0x73, 0x81,
            0xAE, 0xF0, 0x5B, 0xB0, 0x2A, 0x66, 0xEC, 0xD0,
            0x12, 0x77, 0x30, 0x62, 0xCF, 0x3F, 0xA2, 0x54,
            0x9E, 0x44, 0xF5, 0x8E, 0xD2, 0x40, 0x17, 0x10
        };

        const unsigned char pk[32] = {
            0x25, 0xD1, 0xDF, 0xF9, 0x51, 0x05, 0xF5, 0x25,
            0x3C, 0x40, 0x22, 0xF6, 0x28, 0xA9, 0x96, 0xAD,
            0x3A, 0x0D, 0x95, 0xFB, 0xF2, 0x1D, 0x46, 0x8A,
            0x1B, 0x33, 0xF8, 0xC1, 0x60, 0xD8, 0xF5, 0x17
        };

        const unsigned char aux_rand[32] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };

        const unsigned char msg[32] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };

        const unsigned char adaptor[33] = {
            0x03, 0x97, 0x72, 0x0B, 0x39, 0x10, 0x29, 0xF5,
            0x79, 0xF1, 0xF5, 0x71, 0x73, 0x35, 0x0B, 0x76,
            0xE4, 0xA7, 0xC3, 0xF4, 0x71, 0x53, 0xA5, 0x0E,
            0x46, 0xFA, 0x3A, 0x5F, 0x08, 0xBE, 0x66, 0xB1, 0x4A
        };

        const unsigned char pre_sig[65] = {
            0x02, 0xC9, 0x74, 0xF5, 0x2A, 0xEC, 0xE9, 0x7C,
            0x75, 0xE4, 0x40, 0xA8, 0xD8, 0x67, 0x7F, 0xC5,
            0x10, 0x5D, 0x85, 0x12, 0x28, 0x7B, 0x9C, 0x03,
            0x04, 0xFA, 0x8D, 0x51, 0xF0, 0xBF, 0x48, 0x60,
            0xBA, 0xA5, 0x30, 0x46, 0xD2, 0x22, 0x1B, 0xB1,
            0x23, 0xBA, 0x04, 0x5F, 0xF5, 0xE5, 0xBD, 0x26,
            0xD8, 0x8D, 0x0B, 0xF0, 0xD6, 0x3B, 0x80, 0xE6,
            0x40, 0x59, 0x99, 0xC1, 0xD2, 0xB6, 0xFF, 0x00, 0x71
        };
        test_schnorr_adaptor_spec_vectors_check_presigning(sk, pk, aux_rand, msg, adaptor, pre_sig);
        test_schnorr_adaptor_spec_vectors_check_extract(pk, msg, adaptor, pre_sig, 1);
    };
    {
        /* Presig: Test vector 2 */

    };
}

static void test_schnorr_adaptor_presign(void) {
    unsigned char sk[32];
    secp256k1_xonly_pubkey pk;
    secp256k1_keypair keypair;
    secp256k1_scalar adaptor_scalar;
    secp256k1_gej tj;
    secp256k1_ge tg;
    const unsigned char msg[32] = "this is for the schnorr adaptor.";
    unsigned char sig[65];
    unsigned char sig2[65];
    unsigned char secadaptor[32];
    unsigned char aux_rand[32];
    unsigned char adaptor33[33];
    secp256k1_pubkey t;
    secp256k1_pubkey adaptor;
    size_t size = 33;

    secp256k1_testrand256(sk);
    secp256k1_testrand256(secadaptor);
    secp256k1_testrand256(aux_rand);
    secp256k1_scalar_set_b32(&adaptor_scalar, secadaptor, NULL);
    secp256k1_ecmult_gen(&CTX->ecmult_gen_ctx, &tj, &adaptor_scalar);
    secp256k1_ge_set_gej(&tg, &tj);
    CHECK(secp256k1_eckey_pubkey_serialize(&tg, adaptor33, &size, 1) == 1);
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
    CHECK(secp256k1_keypair_xonly_pub(CTX, &pk, NULL, &keypair) == 1);
    CHECK(secp256k1_ec_pubkey_parse(CTX, &adaptor, adaptor33, 33) == 1);
    CHECK(secp256k1_schnorr_adaptor_presign(CTX, sig, msg, &keypair, &adaptor, NULL) == 1);
    CHECK(secp256k1_schnorr_adaptor_extract(CTX, &t, sig, msg, &pk));
    CHECK(secp256k1_ec_pubkey_cmp(CTX, &t, &adaptor) == 0);
    /* Test with aux_rand */
    CHECK(secp256k1_schnorr_adaptor_presign(CTX, sig2, msg, &keypair, &adaptor, aux_rand) == 1);
    CHECK(secp256k1_schnorr_adaptor_extract(CTX, &t, sig, msg, &pk));
    CHECK(secp256k1_ec_pubkey_cmp(CTX, &t, &adaptor) == 0);
}

#define N_SIGS 3
/* Creates N_SIGS valid signatures and verifies them with extract
 * Then flips some bits and checks that extract now fails to get the right
 * adaptor point. */
static void test_schnorr_adaptor_extract(void) {
    unsigned char sk[32];
    secp256k1_xonly_pubkey pk;
    secp256k1_keypair keypair;
    secp256k1_scalar adaptor_scalar;
    secp256k1_gej tj;
    secp256k1_ge tg;
    secp256k1_scalar s;
    unsigned char msg[N_SIGS][32];
    unsigned char sig[N_SIGS][65];
    unsigned char secadaptor[N_SIGS][32];
    unsigned char adaptor33[N_SIGS][33];
    secp256k1_pubkey t;
    secp256k1_pubkey adaptor[N_SIGS];
    size_t size = 33;
    size_t i;

    secp256k1_testrand256(sk);
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
    CHECK(secp256k1_keypair_xonly_pub(CTX, &pk, NULL, &keypair) == 1);

    for (i = 0; i < N_SIGS; i++) {
        secp256k1_testrand256(msg[i]);
        secp256k1_testrand256(secadaptor[i]);
        secp256k1_scalar_set_b32(&adaptor_scalar, secadaptor[i], NULL);
        secp256k1_ecmult_gen(&CTX->ecmult_gen_ctx, &tj, &adaptor_scalar);
        secp256k1_ge_set_gej(&tg, &tj);
        CHECK(secp256k1_eckey_pubkey_serialize(&tg, adaptor33[i], &size, 1) == 1);
        CHECK(secp256k1_ec_pubkey_parse(CTX, &adaptor[i], adaptor33[i], 33) == 1);
        CHECK(secp256k1_schnorr_adaptor_presign(CTX, sig[i], msg[i], &keypair, &adaptor[i], NULL) == 1);
        CHECK(secp256k1_schnorr_adaptor_extract(CTX, &t, sig[i], msg[i], &pk));
        CHECK(secp256k1_ec_pubkey_cmp(CTX, &t, &adaptor[i]) == 0);
    }

    {
        /* Flip some bits in the signature and check that extract fails to
         * extract the correct adaptor point */
        size_t sig_idx = secp256k1_testrand_int(N_SIGS);
        size_t byte_idx = secp256k1_testrand_bits(5);
        unsigned char xorbyte = secp256k1_testrand_int(254)+1;
        sig[sig_idx][33 + byte_idx] ^= xorbyte;
        CHECK(secp256k1_schnorr_adaptor_extract(CTX, &t, sig[sig_idx], msg[sig_idx], &pk));
        CHECK(secp256k1_ec_pubkey_cmp(CTX, &t, &adaptor[sig_idx]) != 0);
        sig[sig_idx][33 + byte_idx] ^= xorbyte;

        CHECK(secp256k1_schnorr_adaptor_extract(CTX, &t, sig[sig_idx], msg[sig_idx], &pk));
        CHECK(secp256k1_ec_pubkey_cmp(CTX, &t, &adaptor[sig_idx]) == 0);
    }

    /* Test overflowing s */
    CHECK(secp256k1_schnorr_adaptor_presign(CTX, sig[0], msg[0], &keypair, &adaptor[0], NULL) == 1);
    CHECK(secp256k1_schnorr_adaptor_extract(CTX, &t, sig[0], msg[0], &pk));
    CHECK(secp256k1_ec_pubkey_cmp(CTX, &t, &adaptor[0]) == 0);
    memset(&sig[0][33], 0xFF, 32);
    CHECK(!secp256k1_schnorr_adaptor_extract(CTX, &t, sig[0], msg[0], &pk));

    /* Test negative s */
    CHECK(secp256k1_schnorr_adaptor_presign(CTX, sig[0], msg[0], &keypair, &adaptor[0], NULL) == 1);
    CHECK(secp256k1_schnorr_adaptor_extract(CTX, &t, sig[0], msg[0], &pk));
    CHECK(secp256k1_ec_pubkey_cmp(CTX, &t, &adaptor[0]) == 0);
    secp256k1_scalar_set_b32(&s, &sig[0][33], NULL);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_scalar_get_b32(&sig[0][33], &s);
    CHECK(secp256k1_schnorr_adaptor_extract(CTX, &t, sig[0], msg[0], &pk));
    CHECK(secp256k1_ec_pubkey_cmp(CTX, &t, &adaptor[0]) != 0);
}
#undef N_SIGS

static void test_schnorr_adaptor_adapt_extract_sec(void) {
    unsigned char sk[32];
    secp256k1_xonly_pubkey pk;
    secp256k1_keypair keypair;
    secp256k1_scalar adaptor_scalar;
    secp256k1_gej tj;
    secp256k1_ge tg;
    unsigned char msg[32];
    unsigned char sig[65];
    unsigned char sig64[64];
    unsigned char secadaptor[32];
    unsigned char aux_rand[32];
    unsigned char adaptor33[33];
    secp256k1_pubkey t;
    unsigned char t2[32];
    secp256k1_pubkey adaptor;
    size_t size = 33;

    secp256k1_testrand256(sk);
    secp256k1_testrand256(msg);
    secp256k1_testrand256(secadaptor);
    secp256k1_testrand256(aux_rand);
    secp256k1_scalar_set_b32(&adaptor_scalar, secadaptor, NULL);
    secp256k1_ecmult_gen(&CTX->ecmult_gen_ctx, &tj, &adaptor_scalar);
    secp256k1_ge_set_gej(&tg, &tj);
    CHECK(secp256k1_eckey_pubkey_serialize(&tg, adaptor33, &size, 1) == 1);
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
    CHECK(secp256k1_keypair_xonly_pub(CTX, &pk, NULL, &keypair) == 1);
    CHECK(secp256k1_ec_pubkey_parse(CTX, &adaptor, adaptor33, 33) == 1);
    CHECK(secp256k1_schnorr_adaptor_presign(CTX, sig, msg, &keypair, &adaptor, aux_rand) == 1);
    CHECK(secp256k1_schnorr_adaptor_extract(CTX, &t, sig, msg, &pk));
    CHECK(secp256k1_ec_pubkey_cmp(CTX, &t, &adaptor) == 0);
    CHECK(secp256k1_schnorr_adaptor_adapt(CTX, sig64, sig, secadaptor) == 1);
    CHECK(secp256k1_schnorrsig_verify(CTX, sig64, msg, sizeof(msg), &pk) == 1);
    CHECK(secp256k1_schnorr_adaptor_extract_sec(CTX, t2, sig, sig64) == 1);
    CHECK(secp256k1_memcmp_var(t2, secadaptor, 32) == 0);
}

static void run_schnorr_adaptor_tests(void) {
    int i;
    run_nonce_function_schnorr_adaptor_tests();

    test_schnorr_adaptor_api();
    test_schnorrsig_sha256_tagged();
    test_schnorr_adaptor_vectors();
    for (i = 0; i < COUNT; i++) {
        test_schnorr_adaptor_presign();
        test_schnorr_adaptor_extract();
        test_schnorr_adaptor_adapt_extract_sec();
    }
}

#endif
