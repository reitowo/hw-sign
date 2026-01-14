#include "app/openssl_demo.h"

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

static void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int TestECDSAPlusECDH() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // Step 1: Create EC Key
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); // secp256r1
    if (!ec_key || !EC_KEY_generate_key(ec_key)) handleErrors();

    // Step 2: ECDSA Sign
    const char* msg = "hello world";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)msg, std::strlen(msg), hash);

    unsigned char sig[256];
    unsigned int sig_len;

    if (!ECDSA_sign(0, hash, sizeof(hash), sig, &sig_len, ec_key))
        handleErrors();

    std::printf("ECDSA signature generated (len = %d)\n", sig_len);

    // Step 3: ECDSA Verify
    int verify_ok = ECDSA_verify(0, hash, sizeof(hash), sig, sig_len, ec_key);
    std::printf("ECDSA signature verification: %s\n", verify_ok == 1 ? "success" : "fail");

    // Step 4: ECDH key exchange with a peer key
    EC_KEY* peer_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!peer_key || !EC_KEY_generate_key(peer_key)) handleErrors();

    // Derive shared secret
    unsigned char secret[256];
    int secret_len = ECDH_compute_key(
        secret,
        sizeof(secret),
        EC_KEY_get0_public_key(peer_key),
        ec_key,
        NULL
    );

    if (secret_len <= 0) handleErrors();
    std::printf("ECDH shared secret computed (len = %d)\n", secret_len);

    // Cleanup
    EC_KEY_free(ec_key);
    EC_KEY_free(peer_key);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}

