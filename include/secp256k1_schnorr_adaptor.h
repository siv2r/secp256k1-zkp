#ifndef SECP256K1_SCHNORR_ADAPTOR_H
#define SECP256K1_SCHNORR_ADAPTOR_H

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

/** A pointer to a function to deterministically generate a nonce.
 *
 *  Same as secp256k1_schnorrsig_nonce function with the exception of using the
 *  compressed 33-byte encoding for the adaptor argument
 *
 *  Returns: 1 if a nonce was successfully generated. 0 will cause signing to
 *           return an error.
 *  Out:  nonce32: pointer to a 32-byte array to be filled by the function
 *  In:     msg32: the 32-byte message being verified (will not be NULL)
 *          key32: pointer to a 32-byte secret key (will not be NULL)
*       adaptor33: the 33-byte serialized adaptor point (will not be NULL)
 *     xonly_pk32: the 32-byte serialized xonly pubkey corresponding to key32
 *                 (will not be NULL)
 *           algo: pointer to an array describing the signature
 *                 algorithm (will not be NULL)
 *        algolen: the length of the algo array
 *           data: arbitrary data pointer that is passed through
 *
 *  Except for test cases, this function should compute some cryptographic hash of
 *  the message, the key, the adaptor point, the pubkey, the algorithm description, and data.
 */
typedef int (*secp256k1_nonce_function_hardened_schnorr_adaptor)(
    unsigned char *nonce32,
    const unsigned char *msg32,
    const unsigned char *key32,
    const unsigned char *adaptor33,
    const unsigned char *xonly_pk32,
    const unsigned char *algo,
    size_t algolen,
    void *data
);

/** A Schnorr Adaptor nonce generation function. */
SECP256K1_API const secp256k1_nonce_function_hardened_schnorr_adaptor secp256k1_nonce_function_schnorr_adaptor;

/** Creates a Schnorr pre-signature.
 *  TODO: this description could be improved & do we really need the
 *  below paragraph?
 *
 *  This function only signs 32-byte messages. If you have messages of a
 *  different size (or the same size but without a context-specific tag
 *  prefix), it is recommended to create a 32-byte message hash with
 *  secp256k1_tagged_sha256 and then sign the hash. Tagged hashing allows
 *  providing an context-specific tag for domain separation. This prevents
 *  signatures from being valid in multiple contexts by accident.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:       ctx: pointer to a context object (not secp256k1_context_static).
 *  Out:   pre_sig65: pointer to a 65-byte array to store the serialized pre-signature.
 *  In:       msg32: the 32-byte message being signed.
 *          keypair: pointer to an initialized keypair.
 *          adaptor: pointer to an adaptor point encoded as a public key.
 *       aux_rand32: pointer to arbitrary data used by the nonce generation
 *                   function (can be NULL). If it is non-NULL and
 *                   secp256k1_nonce_function_schnorr_adaptor is used, then
 *                   aux_rand32 must be a pointer to 32-byte auxiliary randomness
 *                   as per BIP-340.
 */
SECP256K1_API int secp256k1_schnorr_adaptor_presign(
    const secp256k1_context *ctx,
    unsigned char *pre_sig65,
    const unsigned char *msg32,
    const secp256k1_keypair *keypair,
    const secp256k1_pubkey *adaptor,
    const unsigned char *aux_rand32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Extract an adaptor point from the pre-signature.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:         ctx: pointer to a context object.
 *  Out:      adaptor: pointer to an adaptor point.
 *  In:      pre_sig65: pointer to a 65-byte pre-signature.
 *              msg32: the 32-byte message being signed.
 *             pubkey: pointer to the x-only public key used to
 *                     generate the `pre_sig65`
 */
SECP256K1_API int secp256k1_schnorr_adaptor_extract(
    const secp256k1_context *ctx,
    secp256k1_pubkey *adaptor,
    const unsigned char *pre_sig65,
    const unsigned char *msg32,
    const secp256k1_xonly_pubkey *pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Creates a signature from a pre-signature and a secret adaptor.
 *
 *  If the sec_adaptor32 argument is incorrect, the output signature will be
 *  invalid. This function does not verify the signature.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:           ctx: pointer to a context object.
 *  Out:          sig64: 64-byte signature. This pointer may point to the same
 *                     memory area as `pre_sig65`.
 *  In:       pre_sig65: 65-byte pre-signature
 *        sec_adaptor32: pointer to a 32-byte secret adaptor.
 */
SECP256K1_API int secp256k1_schnorr_adaptor_adapt(
    const secp256k1_context *ctx,
    unsigned char *sig64,
    const unsigned char *pre_sig65,
    const unsigned char *sec_adaptor32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Extracts a secret adaptor from a pre-signature and the corresponding
 *  signature.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:           ctx: pointer to a context object.
 *  Out:  sec_adaptor32: 32-byte secret adaptor.
 *  In:       pre_sig65: the pre-signature corresponding to `sig64`
 *                sig64: complete, valid 64-byte signature.
 */
/* TODO: swap the presig and sig arg order */
SECP256K1_API int secp256k1_schnorr_adaptor_extract_sec(
    const secp256k1_context *ctx,
    unsigned char *sec_adaptor32,
    const unsigned char *pre_sig65,
    const unsigned char *sig64
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SCHNORR_ADAPTOR_H */
