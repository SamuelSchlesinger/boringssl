// Copyright 2025 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <openssl/trust_token.h>

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/rand.h>
#include <openssl/sha2.h>

#include "../ec/internal.h"
#include "../fipsmodule/bn/internal.h"
#include "../fipsmodule/ec/internal.h"
#include "../mem_internal.h"

#include "internal.h"


using namespace bssl;

// ATHM (Anonymous Tokens with Hidden Metadata) implementation.
//
// This implements the ATHM protocol from draft-yun-cfrg-athm-00 using P-256
// with nBuckets=4 hidden metadata buckets.
//
// Key field mapping in TRUST_TOKEN_ISSUER_KEY:
//   x0 = x, y0 = y, x1 = r_x, y1 = r_y, xs = z
//   pub0 = C_x, pub1 = C_y, pubs = Z
//
// Protocol summary:
//   Private Key: (x, y, z, r_x, r_y)
//   Public Key:  (Z, C_x, C_y, proof) where Z=z*G, C_x=x*G+r_x*H,
//                C_y=y*G+r_y*H
//   TokenRequest:   T = r*G + tc*Z
//   TokenResponse:  U = d*G, V = d*(x*G + metadata*y*G + ts*Z + T), + proof
//   FinalizeToken:  P = c*U, Q = c*(V - r*U), t = tc + ts
//   VerifyToken:    Q == (x + t*z + metadata*y)*P

static const size_t kNBuckets = 4;

static const uint8_t kDefaultAdditionalData[32] = {0};

typedef struct {
  const EC_GROUP *group;
  EC_JACOBIAN h;
  // context_string = "ATHMV1-P256-4-" + deploymentId
  uint8_t *context_string;
  size_t context_string_len;
} ATHM_METHOD;

static void athm_method_cleanup(ATHM_METHOD *method) {
  OPENSSL_free(method->context_string);
  method->context_string = nullptr;
  method->context_string_len = 0;
}

// ec_jacobian_to_affine_serial converts |num| Jacobian points to affine,
// one at a time.
static int ec_jacobian_to_affine_serial(const EC_GROUP *group, EC_AFFINE *out,
                                         const EC_JACOBIAN *in, size_t num) {
  for (size_t i = 0; i < num; i++) {
    if (!ec_jacobian_to_affine(group, &out[i], &in[i])) {
      return 0;
    }
  }
  return 1;
}

// Compressed point serialization (33 bytes for P-256).
static int point_to_cbb(CBB *out, const EC_GROUP *group,
                         const EC_AFFINE *point) {
  size_t len = ec_point_byte_len(group, POINT_CONVERSION_COMPRESSED);
  if (len == 0) {
    return 0;
  }
  uint8_t *p;
  return CBB_add_space(out, &p, len) &&
         ec_point_to_bytes(group, point, POINT_CONVERSION_COMPRESSED, p,
                           len) == len;
}

// I2OSP(len, 2) || data — transcript element with 2-byte big-endian length
// prefix.
static int transcript_add_point(CBB *cbb, const EC_GROUP *group,
                                const EC_AFFINE *point) {
  size_t len = ec_point_byte_len(group, POINT_CONVERSION_COMPRESSED);
  if (len == 0) {
    return 0;
  }
  uint8_t *p;
  return CBB_add_u16(cbb, len) && CBB_add_space(cbb, &p, len) &&
         ec_point_to_bytes(group, point, POINT_CONVERSION_COMPRESSED, p,
                           len) == len;
}

static int transcript_add_scalar(CBB *cbb, const EC_GROUP *group,
                                 const EC_SCALAR *scalar) {
  size_t scalar_len = BN_num_bytes(EC_GROUP_get0_order(group));
  uint8_t *buf;
  return CBB_add_u16(cbb, scalar_len) && CBB_add_space(cbb, &buf, scalar_len) &&
         (ec_scalar_to_bytes(group, buf, &scalar_len, scalar), 1);
}

static int cbs_get_point(CBS *cbs, const EC_GROUP *group, EC_AFFINE *out) {
  size_t plen = ec_point_byte_len(group, POINT_CONVERSION_COMPRESSED);
  CBS child;
  if (!CBS_get_bytes(cbs, &child, plen)) {
    return 0;
  }
  // Decompress via EC_POINT_oct2point which handles compressed format, then
  // extract the internal jacobian representation and convert to affine.
  EC_POINT *pt = EC_POINT_new(group);
  if (pt == nullptr) {
    return 0;
  }
  int ok = EC_POINT_oct2point(group, pt, CBS_data(&child), CBS_len(&child),
                              nullptr) &&
           ec_jacobian_to_affine(group, out, &pt->raw);
  EC_POINT_free(pt);
  return ok;
}

static int scalar_to_cbb(CBB *out, const EC_GROUP *group,
                          const EC_SCALAR *scalar) {
  uint8_t *buf;
  size_t scalar_len = BN_num_bytes(EC_GROUP_get0_order(group));
  if (!CBB_add_space(out, &buf, scalar_len)) {
    return 0;
  }
  ec_scalar_to_bytes(group, buf, &scalar_len, scalar);
  return 1;
}

static int scalar_from_cbs(CBS *cbs, const EC_GROUP *group, EC_SCALAR *out) {
  size_t scalar_len = BN_num_bytes(EC_GROUP_get0_order(group));
  CBS tmp;
  if (!CBS_get_bytes(cbs, &tmp, scalar_len) ||
      !ec_scalar_from_bytes(group, out, CBS_data(&tmp), CBS_len(&tmp))) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return 0;
  }

  return 1;
}

// Build a context string "ATHMV1-P256-4-" + deployment_id.
static int build_context_string(uint8_t **out, size_t *out_len,
                                const uint8_t *deployment_id,
                                size_t deployment_id_len) {
  static const char kPrefix[] = "ATHMV1-P256-4-";
  CBB cbb;
  CBB_zero(&cbb);
  if (!CBB_init(&cbb, sizeof(kPrefix) - 1 + deployment_id_len) ||
      !CBB_add_bytes(&cbb, reinterpret_cast<const uint8_t *>(kPrefix),
                     sizeof(kPrefix) - 1) ||
      !CBB_add_bytes(&cbb, deployment_id, deployment_id_len) ||
      !CBB_finish(&cbb, out, out_len)) {
    CBB_cleanup(&cbb);
    return 0;
  }
  return 1;
}

// athm_hash_to_scalar hashes |msg| to a scalar using DST =
// "HashToScalar-" + context_string + info.
static int athm_hash_to_scalar(const ATHM_METHOD *method, EC_SCALAR *out,
                                const uint8_t *msg, size_t msg_len,
                                const char *info, size_t info_len) {
  static const char kDSTPrefix[] = "HashToScalar-";
  CBB cbb;
  CBB_zero(&cbb);
  uint8_t *dst = nullptr;
  size_t dst_len;
  if (!CBB_init(&cbb, 0) ||
      !CBB_add_bytes(&cbb, reinterpret_cast<const uint8_t *>(kDSTPrefix),
                     sizeof(kDSTPrefix) - 1) ||
      !CBB_add_bytes(&cbb, method->context_string,
                     method->context_string_len) ||
      !CBB_add_bytes(&cbb, reinterpret_cast<const uint8_t *>(info),
                     info_len) ||
      !CBB_finish(&cbb, &dst, &dst_len)) {
    CBB_cleanup(&cbb);
    return 0;
  }

  int ok = ec_hash_to_scalar_p256_xmd_sha256(method->group, out, dst, dst_len,
                                              msg, msg_len);
  OPENSSL_free(dst);
  return ok;
}

static int athm_init_method(ATHM_METHOD *method, const EC_GROUP *group,
                             const EC_JACOBIAN *h,
                             const uint8_t *deployment_id,
                             size_t deployment_id_len) {
  method->group = group;
  method->h = *h;
  method->context_string = nullptr;
  method->context_string_len = 0;
  if (!build_context_string(&method->context_string, &method->context_string_len,
                            deployment_id, deployment_id_len)) {
    return 0;
  }
  return 1;
}

static int derive_scalar_from_secret(const ATHM_METHOD *method,
                                     EC_SCALAR *out, const uint8_t *secret,
                                     size_t secret_len, uint8_t scalar_id) {
  static const char kInfo[] = "KeyGen";

  int ok = 0;
  CBB cbb;
  CBB_zero(&cbb);
  uint8_t *buf = nullptr;
  size_t len;
  if (!CBB_init(&cbb, 0) ||
      !CBB_add_u8(&cbb, scalar_id) ||
      !CBB_add_bytes(&cbb, secret, secret_len) ||
      !CBB_finish(&cbb, &buf, &len) ||
      !athm_hash_to_scalar(method, out, buf, len, kInfo, sizeof(kInfo) - 1) ||
      ec_scalar_is_zero(method->group, out)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_KEYGEN_FAILURE);
    goto err;
  }

  ok = 1;

err:
  CBB_cleanup(&cbb);
  OPENSSL_free(buf);
  return ok;
}


// CreatePublicKeyProof per draft-yun-cfrg-athm-00:
//   rho_z = RandomScalar()
//   gamma_z = rho_z * G
//   transcript = I2OSP(len(G),2) || G || I2OSP(len(Z),2) || Z ||
//                I2OSP(len(gamma_z),2) || gamma_z
//   e = HashToScalar(transcript, "KeyCommitments")
//   a_z = rho_z - e * z
static int create_public_key_proof(const ATHM_METHOD *method,
                                   EC_SCALAR *out_e, EC_SCALAR *out_az,
                                   const EC_SCALAR *z,
                                   const EC_AFFINE *Z_affine) {
  const EC_GROUP *group = method->group;

  EC_SCALAR rho_z;
  if (!ec_random_nonzero_scalar(group, &rho_z, kDefaultAdditionalData)) {
    return 0;
  }

  // gamma_z = rho_z * G
  EC_JACOBIAN gamma_j;
  EC_AFFINE gamma;
  if (!ec_point_mul_scalar_base(group, &gamma_j, &rho_z) ||
      !ec_jacobian_to_affine(group, &gamma, &gamma_j)) {
    return 0;
  }

  // Get generator G in affine form.
  EC_SCALAR one;
  OPENSSL_memset(&one, 0, sizeof(one));
  {
    uint8_t one_bytes[EC_MAX_BYTES] = {0};
    size_t slen = BN_num_bytes(EC_GROUP_get0_order(group));
    one_bytes[slen - 1] = 1;
    if (!ec_scalar_from_bytes(group, &one, one_bytes, slen)) {
      return 0;
    }
  }
  EC_JACOBIAN G_j;
  EC_AFFINE G_affine;
  if (!ec_point_mul_scalar_base(group, &G_j, &one) ||
      !ec_jacobian_to_affine(group, &G_affine, &G_j)) {
    return 0;
  }

  // transcript = I2OSP(len(G),2)||G || I2OSP(len(Z),2)||Z ||
  //              I2OSP(len(gamma_z),2)||gamma_z
  int ok = 0;
  CBB cbb;
  CBB_zero(&cbb);
  uint8_t *buf = nullptr;
  size_t len;
  if (!CBB_init(&cbb, 0) ||
      !transcript_add_point(&cbb, group, &G_affine) ||
      !transcript_add_point(&cbb, group, Z_affine) ||
      !transcript_add_point(&cbb, group, &gamma) ||
      !CBB_finish(&cbb, &buf, &len) ||
      !athm_hash_to_scalar(method, out_e, buf, len, "KeyCommitments",
                            sizeof("KeyCommitments") - 1)) {
    goto err;
  }

  // a_z = rho_z - e * z
  {
    EC_SCALAR e_mont;
    ec_scalar_to_montgomery(group, &e_mont, out_e);
    ec_scalar_mul_montgomery(group, out_az, z, &e_mont);
    ec_scalar_sub(group, out_az, &rho_z, out_az);
  }

  ok = 1;

err:
  CBB_cleanup(&cbb);
  OPENSSL_free(buf);
  return ok;
}

// VerifyPublicKeyProof per draft-yun-cfrg-athm-00:
//   gamma_z = e*Z + a_z*G
//   (recompute transcript, check e matches)
static int verify_public_key_proof(const ATHM_METHOD *method,
                                   const EC_AFFINE *Z_affine,
                                   const EC_SCALAR *e, const EC_SCALAR *a_z) {
  const EC_GROUP *group = method->group;

  // gamma_z = e*Z + a_z*G
  EC_JACOBIAN Z_j;
  ec_affine_to_jacobian(group, &Z_j, Z_affine);
  EC_JACOBIAN gamma_j;
  if (!ec_point_mul_scalar_public(group, &gamma_j, a_z, &Z_j, e)) {
    return 0;
  }

  EC_AFFINE gamma;
  if (!ec_jacobian_to_affine(group, &gamma, &gamma_j)) {
    return 0;
  }

  // Get generator G.
  EC_SCALAR one;
  OPENSSL_memset(&one, 0, sizeof(one));
  {
    uint8_t one_bytes[EC_MAX_BYTES] = {0};
    size_t slen = BN_num_bytes(EC_GROUP_get0_order(group));
    one_bytes[slen - 1] = 1;
    if (!ec_scalar_from_bytes(group, &one, one_bytes, slen)) {
      return 0;
    }
  }
  EC_JACOBIAN G_j;
  EC_AFFINE G_affine;
  if (!ec_point_mul_scalar_base(group, &G_j, &one) ||
      !ec_jacobian_to_affine(group, &G_affine, &G_j)) {
    return 0;
  }

  // Recompute e' = HashToScalar(transcript, "KeyCommitments")
  int ok = 0;
  CBB cbb;
  CBB_zero(&cbb);
  uint8_t *buf = nullptr;
  size_t len;
  EC_SCALAR e_check;
  if (!CBB_init(&cbb, 0) ||
      !transcript_add_point(&cbb, group, &G_affine) ||
      !transcript_add_point(&cbb, group, Z_affine) ||
      !transcript_add_point(&cbb, group, &gamma) ||
      !CBB_finish(&cbb, &buf, &len) ||
      !athm_hash_to_scalar(method, &e_check, buf, len, "KeyCommitments",
                            sizeof("KeyCommitments") - 1)) {
    goto err;
  }

  if (!ec_scalar_equal_vartime(group, e, &e_check)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_INVALID_PROOF);
    goto err;
  }

  ok = 1;

err:
  CBB_cleanup(&cbb);
  OPENSSL_free(buf);
  return ok;
}


static int athm_compute_keys(const ATHM_METHOD *method, CBB *out_private,
                              CBB *out_public, const EC_SCALAR *x,
                              const EC_SCALAR *y, const EC_SCALAR *z,
                              const EC_SCALAR *r_x, const EC_SCALAR *r_y) {
  const EC_GROUP *group = method->group;

  // Z = z*G
  // C_x = x*G + r_x*H
  // C_y = y*G + r_y*H
  EC_JACOBIAN pub[3];
  EC_JACOBIAN tmp1, tmp2;
  if (!ec_point_mul_scalar_base(group, &pub[0], z)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_KEYGEN_FAILURE);
    return 0;
  }

  if (!ec_point_mul_scalar_base(group, &tmp1, x) ||
      !ec_point_mul_scalar(group, &tmp2, &method->h, r_x)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_KEYGEN_FAILURE);
    return 0;
  }
  group->meth->add(group, &pub[1], &tmp1, &tmp2);

  if (!ec_point_mul_scalar_base(group, &tmp1, y) ||
      !ec_point_mul_scalar(group, &tmp2, &method->h, r_y)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_KEYGEN_FAILURE);
    return 0;
  }
  group->meth->add(group, &pub[2], &tmp1, &tmp2);

  // Serialize private key: x, y, r_x, r_y, z (5 scalars)
  const EC_SCALAR *scalars[] = {x, y, r_x, r_y, z};
  size_t scalar_len = BN_num_bytes(EC_GROUP_get0_order(group));
  for (const EC_SCALAR *scalar : scalars) {
    uint8_t *buf;
    if (!CBB_add_space(out_private, &buf, scalar_len)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_BUFFER_TOO_SMALL);
      return 0;
    }
    ec_scalar_to_bytes(group, buf, &scalar_len, scalar);
  }

  // Serialize public key: Z || C_x || C_y || proof_e || proof_az
  // (all compressed points)
  EC_AFFINE pub_affine[3];
  if (!ec_jacobian_to_affine_serial(group, pub_affine, pub, 3)) {
    return 0;
  }

  EC_SCALAR proof_e, proof_az;
  if (!create_public_key_proof(method, &proof_e, &proof_az, z,
                               &pub_affine[0])) {
    return 0;
  }

  if (!point_to_cbb(out_public, group, &pub_affine[0]) ||   // Z
      !point_to_cbb(out_public, group, &pub_affine[1]) ||   // C_x
      !point_to_cbb(out_public, group, &pub_affine[2]) ||   // C_y
      !scalar_to_cbb(out_public, group, &proof_e) ||
      !scalar_to_cbb(out_public, group, &proof_az)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_BUFFER_TOO_SMALL);
    return 0;
  }

  return 1;
}

static int athm_generate_key(const ATHM_METHOD *method, CBB *out_private,
                              CBB *out_public) {
  EC_SCALAR x, y, z, r_x, r_y;
  if (!ec_random_nonzero_scalar(method->group, &x, kDefaultAdditionalData) ||
      !ec_random_nonzero_scalar(method->group, &y, kDefaultAdditionalData) ||
      !ec_random_nonzero_scalar(method->group, &z, kDefaultAdditionalData) ||
      !ec_random_nonzero_scalar(method->group, &r_x, kDefaultAdditionalData) ||
      !ec_random_nonzero_scalar(method->group, &r_y, kDefaultAdditionalData)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_KEYGEN_FAILURE);
    return 0;
  }

  return athm_compute_keys(method, out_private, out_public, &x, &y, &z, &r_x,
                            &r_y);
}

static int athm_derive_key_from_secret(const ATHM_METHOD *method,
                                        CBB *out_private, CBB *out_public,
                                        const uint8_t *secret,
                                        size_t secret_len) {
  EC_SCALAR x, y, z, r_x, r_y;
  if (!derive_scalar_from_secret(method, &x, secret, secret_len, 0) ||
      !derive_scalar_from_secret(method, &y, secret, secret_len, 1) ||
      !derive_scalar_from_secret(method, &z, secret, secret_len, 2) ||
      !derive_scalar_from_secret(method, &r_x, secret, secret_len, 3) ||
      !derive_scalar_from_secret(method, &r_y, secret, secret_len, 4)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_KEYGEN_FAILURE);
    return 0;
  }

  return athm_compute_keys(method, out_private, out_public, &x, &y, &z, &r_x,
                            &r_y);
}

static int athm_client_key_from_bytes(const ATHM_METHOD *method,
                                       TRUST_TOKEN_CLIENT_KEY *key,
                                       const uint8_t *in, size_t len) {
  const EC_GROUP *group = method->group;
  CBS cbs;
  CBS_init(&cbs, in, len);

  if (!cbs_get_point(&cbs, group, &key->pubs) ||    // Z
      !cbs_get_point(&cbs, group, &key->pub0) ||    // C_x
      !cbs_get_point(&cbs, group, &key->pub1)) {    // C_y
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return 0;
  }

  EC_SCALAR proof_e, proof_az;
  if (!scalar_from_cbs(&cbs, group, &proof_e) ||
      !scalar_from_cbs(&cbs, group, &proof_az) ||
      CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return 0;
  }

  if (!verify_public_key_proof(method, &key->pubs, &proof_e, &proof_az)) {
    return 0;
  }

  return 1;
}

static int athm_issuer_key_from_bytes(const ATHM_METHOD *method,
                                       TRUST_TOKEN_ISSUER_KEY *key,
                                       const uint8_t *in, size_t len) {
  const EC_GROUP *group = method->group;
  CBS cbs, tmp;
  CBS_init(&cbs, in, len);
  size_t scalar_len = BN_num_bytes(EC_GROUP_get0_order(group));

  // Parse 5 scalars: x, y, r_x, r_y, z
  EC_SCALAR *scalars[] = {&key->x0, &key->y0, &key->x1, &key->y1, &key->xs};
  for (EC_SCALAR *scalar : scalars) {
    if (!CBS_get_bytes(&cbs, &tmp, scalar_len) ||
        !ec_scalar_from_bytes(group, scalar, CBS_data(&tmp), CBS_len(&tmp))) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
      return 0;
    }
  }

  if (CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return 0;
  }

  // Recompute public key.
  EC_JACOBIAN pub[3];
  EC_JACOBIAN tmp1, tmp2;
  EC_AFFINE pub_affine[3];
  if (!ec_point_mul_scalar_base(group, &pub[0], &key->xs)) {
    return 0;
  }

  if (!ec_point_mul_scalar_base(group, &tmp1, &key->x0) ||
      !ec_point_mul_scalar(group, &tmp2, &method->h, &key->x1)) {
    return 0;
  }
  group->meth->add(group, &pub[1], &tmp1, &tmp2);

  if (!ec_point_mul_scalar_base(group, &tmp1, &key->y0) ||
      !ec_point_mul_scalar(group, &tmp2, &method->h, &key->y1)) {
    return 0;
  }
  group->meth->add(group, &pub[2], &tmp1, &tmp2);

  if (!ec_jacobian_to_affine_serial(group, pub_affine, pub, 3)) {
    return 0;
  }

  key->pubs = pub_affine[0];  // Z
  key->pub0 = pub_affine[1];  // C_x
  key->pub1 = pub_affine[2];  // C_y

  return 1;
}

static STACK_OF(TRUST_TOKEN_PRETOKEN) *athm_blind(
    const ATHM_METHOD *method, CBB *cbb, size_t count, int include_message,
    const uint8_t *msg, size_t msg_len, const TRUST_TOKEN_CLIENT_KEY *key) {
  SHA512_CTX hash_ctx;
  const EC_GROUP *group = method->group;

  if (key == nullptr) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_NO_KEYS_CONFIGURED);
    return nullptr;
  }

  STACK_OF(TRUST_TOKEN_PRETOKEN) *pretokens =
      sk_TRUST_TOKEN_PRETOKEN_new_null();
  if (pretokens == nullptr) {
    goto err;
  }

  for (size_t i = 0; i < count; i++) {
    TRUST_TOKEN_PRETOKEN *pretoken = New<TRUST_TOKEN_PRETOKEN>();
    if (pretoken == nullptr ||
        !sk_TRUST_TOKEN_PRETOKEN_push(pretokens, pretoken)) {
      TRUST_TOKEN_PRETOKEN_free(pretoken);
      goto err;
    }

    RAND_bytes(pretoken->salt, sizeof(pretoken->salt));
    if (include_message) {
      assert(SHA512_DIGEST_LENGTH == TRUST_TOKEN_NONCE_SIZE);
      SHA512_Init(&hash_ctx);
      SHA512_Update(&hash_ctx, pretoken->salt, sizeof(pretoken->salt));
      SHA512_Update(&hash_ctx, msg, msg_len);
      SHA512_Final(pretoken->t, &hash_ctx);
    } else {
      OPENSSL_memcpy(pretoken->t, pretoken->salt, TRUST_TOKEN_NONCE_SIZE);
    }

    EC_SCALAR tc;
    if (!ec_random_nonzero_scalar(group, &pretoken->r,
                                  kDefaultAdditionalData) ||
        !ec_random_nonzero_scalar(group, &tc, kDefaultAdditionalData)) {
      goto err;
    }

    // Store tc in the first 32 bytes of salt (already used for nonce).
    size_t scalar_len = BN_num_bytes(EC_GROUP_get0_order(group));
    ec_scalar_to_bytes(group, pretoken->salt, &scalar_len, &tc);

    // T = r*G + tc*Z
    EC_JACOBIAN Z_j;
    ec_affine_to_jacobian(group, &Z_j, &key->pubs);
    EC_JACOBIAN T;
    EC_JACOBIAN rG;
    if (!ec_point_mul_scalar_base(group, &rG, &pretoken->r) ||
        !ec_point_mul_scalar(group, &T, &Z_j, &tc)) {
      goto err;
    }
    group->meth->add(group, &T, &rG, &T);

    if (!ec_jacobian_to_affine(group, &pretoken->Tp, &T)) {
      goto err;
    }

    // Write T (compressed, 33 bytes) to the request.
    if (!point_to_cbb(cbb, group, &pretoken->Tp)) {
      goto err;
    }
  }

  return pretokens;

err:
  sk_TRUST_TOKEN_PRETOKEN_pop_free(pretokens, TRUST_TOKEN_PRETOKEN_free);
  return nullptr;
}

// hash_issuance_transcript hashes the full spec transcript for
// CreateIssuanceProof / VerifyIssuanceProof.
//
// Transcript:
//   I2OSP(33,2) || G
//   I2OSP(33,2) || H
//   I2OSP(33,2) || C_x
//   I2OSP(33,2) || C_y
//   I2OSP(33,2) || Z
//   I2OSP(33,2) || U
//   I2OSP(33,2) || V
//   I2OSP(32,2) || ts
//   I2OSP(33,2) || T
//   I2OSP(33,2) || C
//   for i in 0..3: I2OSP(33,2) || C_vec[i]
//   I2OSP(33,2) || C_d
//   I2OSP(33,2) || C_rho
//   I2OSP(33,2) || C_w
static int hash_issuance_transcript(const ATHM_METHOD *method,
                                    EC_SCALAR *out,
                                    const EC_AFFINE *G_affine,
                                    const EC_AFFINE *H_affine,
                                    const EC_AFFINE *C_x,
                                    const EC_AFFINE *C_y,
                                    const EC_AFFINE *Z,
                                    const EC_AFFINE *U,
                                    const EC_AFFINE *V,
                                    const EC_SCALAR *ts,
                                    const EC_AFFINE *T,
                                    const EC_AFFINE *C_commit,
                                    const EC_AFFINE *C_vec,
                                    size_t num_buckets,
                                    const EC_AFFINE *C_d,
                                    const EC_AFFINE *C_rho,
                                    const EC_AFFINE *C_w) {
  const EC_GROUP *group = method->group;
  int ok = 0;
  CBB cbb;
  CBB_zero(&cbb);
  uint8_t *buf = nullptr;
  size_t len;
  if (!CBB_init(&cbb, 0) ||
      !transcript_add_point(&cbb, group, G_affine) ||
      !transcript_add_point(&cbb, group, H_affine) ||
      !transcript_add_point(&cbb, group, C_x) ||
      !transcript_add_point(&cbb, group, C_y) ||
      !transcript_add_point(&cbb, group, Z) ||
      !transcript_add_point(&cbb, group, U) ||
      !transcript_add_point(&cbb, group, V) ||
      !transcript_add_scalar(&cbb, group, ts) ||
      !transcript_add_point(&cbb, group, T) ||
      !transcript_add_point(&cbb, group, C_commit)) {
    goto err;
  }

  for (size_t i = 0; i < num_buckets; i++) {
    if (!transcript_add_point(&cbb, group, &C_vec[i])) {
      goto err;
    }
  }

  if (!transcript_add_point(&cbb, group, C_d) ||
      !transcript_add_point(&cbb, group, C_rho) ||
      !transcript_add_point(&cbb, group, C_w) ||
      !CBB_finish(&cbb, &buf, &len) ||
      !athm_hash_to_scalar(method, out, buf, len, "TokenResponseProof",
                            sizeof("TokenResponseProof") - 1)) {
    goto err;
  }

  ok = 1;

err:
  CBB_cleanup(&cbb);
  OPENSSL_free(buf);
  return ok;
}

// Helper to make a small integer scalar.
static int make_small_scalar(const EC_GROUP *group, EC_SCALAR *out,
                              uint8_t value) {
  OPENSSL_memset(out, 0, sizeof(EC_SCALAR));
  uint8_t buf[EC_MAX_BYTES] = {0};
  size_t slen = BN_num_bytes(EC_GROUP_get0_order(group));
  buf[slen - 1] = value;
  return ec_scalar_from_bytes(group, out, buf, slen);
}

// Helper to get generator G as an affine point.
static int get_generator_affine(const EC_GROUP *group, EC_AFFINE *out) {
  EC_SCALAR one;
  if (!make_small_scalar(group, &one, 1)) {
    return 0;
  }
  EC_JACOBIAN G_j;
  return ec_point_mul_scalar_base(group, &G_j, &one) &&
         ec_jacobian_to_affine(group, out, &G_j);
}

static int athm_sign(const ATHM_METHOD *method,
                      const TRUST_TOKEN_ISSUER_KEY *key, CBB *cbb, CBS *cbs,
                      size_t num_requested, size_t num_to_issue,
                      uint8_t private_metadata) {
  const EC_GROUP *group = method->group;
  if (num_requested < num_to_issue) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_INTERNAL_ERROR);
    return 0;
  }
  if (private_metadata >= kNBuckets) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_INVALID_METADATA);
    return 0;
  }

  // Get G and H in affine form for transcript.
  EC_AFFINE G_affine, H_affine;
  if (!get_generator_affine(group, &G_affine)) {
    return 0;
  }
  EC_AFFINE h_aff;
  if (!ec_jacobian_to_affine(group, &h_aff, &method->h)) {
    return 0;
  }
  H_affine = h_aff;

  for (size_t i = 0; i < num_to_issue; i++) {
    // Parse T from the request (compressed, 33 bytes).
    EC_AFFINE T_affine;
    if (!cbs_get_point(cbs, group, &T_affine)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
      return 0;
    }
    EC_JACOBIAN T;
    ec_affine_to_jacobian(group, &T, &T_affine);
    if (ec_GFp_simple_is_at_infinity(group, &T)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
      return 0;
    }

    // Generate random d (nonzero) and ts.
    EC_SCALAR d, ts;
    if (!ec_random_nonzero_scalar(group, &d, kDefaultAdditionalData) ||
        !ec_random_nonzero_scalar(group, &ts, kDefaultAdditionalData)) {
      return 0;
    }

    // U = d*G
    EC_JACOBIAN U_j;
    if (!ec_point_mul_scalar_base(group, &U_j, &d)) {
      return 0;
    }

    // V = d*(x*G + metadata*y*G + ts*Z + T)
    EC_SCALAR metadata_scalar;
    if (!make_small_scalar(group, &metadata_scalar, private_metadata)) {
      return 0;
    }

    EC_SCALAR w, tmp_s;
    EC_SCALAR metadata_mont;
    ec_scalar_to_montgomery(group, &metadata_mont, &metadata_scalar);
    ec_scalar_mul_montgomery(group, &tmp_s, &key->y0, &metadata_mont);
    ec_scalar_add(group, &w, &key->x0, &tmp_s);
    EC_SCALAR ts_mont;
    ec_scalar_to_montgomery(group, &ts_mont, &ts);
    ec_scalar_mul_montgomery(group, &tmp_s, &key->xs, &ts_mont);
    ec_scalar_add(group, &w, &w, &tmp_s);

    EC_JACOBIAN wG, inner;
    if (!ec_point_mul_scalar_base(group, &wG, &w)) {
      return 0;
    }
    group->meth->add(group, &inner, &wG, &T);

    EC_JACOBIAN V_j;
    if (!ec_point_mul_scalar(group, &V_j, &inner, &d)) {
      return 0;
    }

    // Convert U, V to affine.
    EC_JACOBIAN jac[2] = {U_j, V_j};
    EC_AFFINE aff[2];
    if (!ec_jacobian_to_affine_serial(group, aff, jac, 2)) {
      return 0;
    }

    // Write U, V, ts to the response.
    if (!point_to_cbb(cbb, group, &aff[0]) ||     // U
        !point_to_cbb(cbb, group, &aff[1]) ||     // V
        !scalar_to_cbb(cbb, group, &ts)) {         // ts
      return 0;
    }

    // === Generate issuance proof (spec structure) ===
    //
    // Random: r_mu, r_d, r_rho, r_w, mu, e_vec[sim], a_vec[sim]
    // C = metadata * C_y + mu * H
    EC_SCALAR mu;
    if (!ec_random_nonzero_scalar(group, &mu, kDefaultAdditionalData)) {
      return 0;
    }

    EC_JACOBIAN C_y_j, C_j;
    ec_affine_to_jacobian(group, &C_y_j, &key->pub1);
    EC_JACOBIAN C_metadata, mu_H;
    if (!ec_point_mul_scalar(group, &C_metadata, &C_y_j, &metadata_scalar) ||
        !ec_point_mul_scalar(group, &mu_H, &method->h, &mu)) {
      return 0;
    }
    group->meth->add(group, &C_j, &C_metadata, &mu_H);

    EC_AFFINE C_affine;
    if (!ec_jacobian_to_affine(group, &C_affine, &C_j)) {
      return 0;
    }

    // Random nonces for the proof.
    EC_SCALAR r_mu, r_d, r_rho, r_w;
    if (!ec_random_nonzero_scalar(group, &r_mu, kDefaultAdditionalData) ||
        !ec_random_nonzero_scalar(group, &r_d, kDefaultAdditionalData) ||
        !ec_random_nonzero_scalar(group, &r_rho, kDefaultAdditionalData) ||
        !ec_random_nonzero_scalar(group, &r_w, kDefaultAdditionalData)) {
      return 0;
    }

    // Per-branch: for simulated branches pick random e_i, a_i.
    EC_SCALAR branch_e[kNBuckets];
    EC_SCALAR branch_a[kNBuckets];

    // Commitment values C_vec[i] for each branch.
    EC_JACOBIAN C_vec_jac[kNBuckets];

    // Compute real branch commitment once: real_C_vec = r_mu * H
    EC_JACOBIAN real_C_vec;
    if (!ec_point_mul_scalar(group, &real_C_vec, &method->h, &r_mu)) {
      return 0;
    }

    EC_SCALAR zero_scalar;
    OPENSSL_memset(&zero_scalar, 0, sizeof(EC_SCALAR));

    for (size_t b = 0; b < kNBuckets; b++) {
      // Always generate random e_i, a_i (simulated path values).
      EC_SCALAR sim_e, sim_a;
      if (!ec_random_nonzero_scalar(group, &sim_e,
                                    kDefaultAdditionalData) ||
          !ec_random_nonzero_scalar(group, &sim_a,
                                    kDefaultAdditionalData)) {
        return 0;
      }

      // Always compute simulated C_vec[i] = a_i*H - e_i*(C - i*C_y)
      EC_SCALAR i_scalar;
      if (!make_small_scalar(group, &i_scalar, (uint8_t)b)) {
        return 0;
      }

      EC_JACOBIAN i_Cy;
      if (!ec_point_mul_scalar(group, &i_Cy, &C_y_j, &i_scalar)) {
        return 0;
      }
      EC_JACOBIAN neg_iCy = i_Cy;
      ec_GFp_simple_invert(group, &neg_iCy);
      EC_JACOBIAN C_minus_iCy;
      group->meth->add(group, &C_minus_iCy, &C_j, &neg_iCy);

      EC_JACOBIAN aiH;
      if (!ec_point_mul_scalar(group, &aiH, &method->h, &sim_a)) {
        return 0;
      }
      EC_SCALAR neg_ei;
      ec_scalar_neg(group, &neg_ei, &sim_e);
      EC_JACOBIAN ei_part;
      if (!ec_point_mul_scalar(group, &ei_part, &C_minus_iCy, &neg_ei)) {
        return 0;
      }
      EC_JACOBIAN sim_C_vec;
      group->meth->add(group, &sim_C_vec, &aiH, &ei_part);

      // Constant-time select: real branch gets zeros and real_C_vec,
      // simulated branch gets random scalars and sim_C_vec.
      crypto_word_t is_real = constant_time_eq_w(b, private_metadata);
      ec_point_select(group, &C_vec_jac[b], is_real, &real_C_vec, &sim_C_vec);
      ec_scalar_select(group, &branch_e[b], is_real, &zero_scalar, &sim_e);
      ec_scalar_select(group, &branch_a[b], is_real, &zero_scalar, &sim_a);
    }

    // Global commitments:
    //   C_d   = r_d * U
    //   C_rho = r_d * V + r_rho * H
    //   C_w   = r_d * V + r_w * G
    EC_JACOBIAN C_d_jac, C_rho_jac, C_w_jac;
    if (!ec_point_mul_scalar(group, &C_d_jac, &U_j, &r_d)) {
      return 0;
    }

    EC_JACOBIAN rdV, rrhoH, rwG;
    if (!ec_point_mul_scalar(group, &rdV, &V_j, &r_d) ||
        !ec_point_mul_scalar(group, &rrhoH, &method->h, &r_rho) ||
        !ec_point_mul_scalar_base(group, &rwG, &r_w)) {
      return 0;
    }
    group->meth->add(group, &C_rho_jac, &rdV, &rrhoH);
    group->meth->add(group, &C_w_jac, &rdV, &rwG);

    // Convert all commitment points to affine.
    EC_JACOBIAN all_jacs[kNBuckets + 3];
    for (size_t b = 0; b < kNBuckets; b++) {
      all_jacs[b] = C_vec_jac[b];
    }
    all_jacs[kNBuckets] = C_d_jac;
    all_jacs[kNBuckets + 1] = C_rho_jac;
    all_jacs[kNBuckets + 2] = C_w_jac;

    EC_AFFINE all_affs[kNBuckets + 3];
    if (!ec_jacobian_to_affine_serial(group, all_affs, all_jacs,
                                     kNBuckets + 3)) {
      return 0;
    }

    // Compute challenge e = HashToScalar(transcript, "TokenResponseProof")
    EC_SCALAR challenge;
    if (!hash_issuance_transcript(method, &challenge, &G_affine, &H_affine,
                                  &key->pub0, &key->pub1, &key->pubs,
                                  &aff[0], &aff[1], &ts, &T_affine,
                                  &C_affine, all_affs, kNBuckets,
                                  &all_affs[kNBuckets],
                                  &all_affs[kNBuckets + 1],
                                  &all_affs[kNBuckets + 2])) {
      return 0;
    }

    // e_vec[real] = e - sum(e_vec[sim])
    // The real branch has e=0, so summing all branch_e values gives the sum
    // of simulated e's without branching on private_metadata.
    EC_SCALAR sum_e;
    OPENSSL_memset(&sum_e, 0, sizeof(EC_SCALAR));
    for (size_t b = 0; b < kNBuckets; b++) {
      ec_scalar_add(group, &sum_e, &sum_e, &branch_e[b]);
    }
    EC_SCALAR e_real;
    ec_scalar_sub(group, &e_real, &challenge, &sum_e);

    // a_vec[real] = r_mu + e_vec[real] * mu
    EC_SCALAR e_real_mont;
    ec_scalar_to_montgomery(group, &e_real_mont, &e_real);
    EC_SCALAR a_real;
    ec_scalar_mul_montgomery(group, &a_real, &mu, &e_real_mont);
    ec_scalar_add(group, &a_real, &r_mu, &a_real);

    // Store e_real and a_real into the correct bucket in constant time.
    for (size_t b = 0; b < kNBuckets; b++) {
      crypto_word_t is_real = constant_time_eq_w(b, private_metadata);
      ec_scalar_select(group, &branch_e[b], is_real, &e_real, &branch_e[b]);
      ec_scalar_select(group, &branch_a[b], is_real, &a_real, &branch_a[b]);
    }

    // d_inv = ScalarInverse(d)
    EC_SCALAR d_mont, d_inv;
    ec_scalar_to_montgomery(group, &d_mont, &d);
    ec_scalar_inv0_montgomery(group, &d_inv, &d_mont);
    // d_inv is now d^{-1} in Montgomery form; convert to normal.
    ec_scalar_from_montgomery(group, &d_inv, &d_inv);

    // rho = -(r_x + metadata*r_y + mu)
    EC_SCALAR rho;
    ec_scalar_mul_montgomery(group, &rho, &key->y1, &metadata_mont);
    ec_scalar_add(group, &rho, &key->x1, &rho);
    ec_scalar_add(group, &rho, &rho, &mu);
    ec_scalar_neg(group, &rho, &rho);

    // w_scalar = x + metadata*y + ts*z
    // (same as w computed above)

    // Global response scalars:
    // a_d   = r_d   - e * d_inv
    // a_rho = r_rho + e * rho
    // a_w   = r_w   + e * w
    EC_SCALAR e_mont;
    ec_scalar_to_montgomery(group, &e_mont, &challenge);

    EC_SCALAR a_d, a_rho, a_w;
    EC_SCALAR e_dinv;
    ec_scalar_mul_montgomery(group, &e_dinv, &d_inv, &e_mont);
    ec_scalar_sub(group, &a_d, &r_d, &e_dinv);

    EC_SCALAR e_rho;
    ec_scalar_mul_montgomery(group, &e_rho, &rho, &e_mont);
    ec_scalar_add(group, &a_rho, &r_rho, &e_rho);

    EC_SCALAR e_w;
    ec_scalar_mul_montgomery(group, &e_w, &w, &e_mont);
    ec_scalar_add(group, &a_w, &r_w, &e_w);

    // Write proof wire format:
    // C[33] e_0[32] e_1[32] e_2[32] e_3[32]
    // a_0[32] a_1[32] a_2[32] a_3[32]
    // a_d[32] a_rho[32] a_w[32]
    if (!point_to_cbb(cbb, group, &C_affine)) {
      return 0;
    }
    for (size_t b = 0; b < kNBuckets; b++) {
      if (!scalar_to_cbb(cbb, group, &branch_e[b])) {
        return 0;
      }
    }
    for (size_t b = 0; b < kNBuckets; b++) {
      if (!scalar_to_cbb(cbb, group, &branch_a[b])) {
        return 0;
      }
    }
    if (!scalar_to_cbb(cbb, group, &a_d) ||
        !scalar_to_cbb(cbb, group, &a_rho) ||
        !scalar_to_cbb(cbb, group, &a_w)) {
      return 0;
    }

    if (!CBB_flush(cbb)) {
      return 0;
    }
  }

  // Skip over any unused requests.
  size_t point_len = ec_point_byte_len(group, POINT_CONVERSION_COMPRESSED);
  if (!CBS_skip(cbs, point_len * (num_requested - num_to_issue))) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return 0;
  }

  return 1;
}

static STACK_OF(TRUST_TOKEN) *athm_unblind(
    const ATHM_METHOD *method, const TRUST_TOKEN_CLIENT_KEY *key,
    const STACK_OF(TRUST_TOKEN_PRETOKEN) *pretokens, CBS *cbs, size_t count,
    uint32_t key_id) {
  const EC_GROUP *group = method->group;
  if (count > sk_TRUST_TOKEN_PRETOKEN_num(pretokens)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return nullptr;
  }

  // Get G and H in affine form.
  EC_AFFINE G_affine, H_affine;
  if (!get_generator_affine(group, &G_affine)) {
    return nullptr;
  }
  if (!ec_jacobian_to_affine(group, &H_affine, &method->h)) {
    return nullptr;
  }

  int ok = 0;
  STACK_OF(TRUST_TOKEN) *ret = sk_TRUST_TOKEN_new_null();
  if (ret == nullptr) {
    goto err;
  }

  for (size_t i = 0; i < count; i++) {
    const TRUST_TOKEN_PRETOKEN *pretoken =
        sk_TRUST_TOKEN_PRETOKEN_value(pretokens, i);

    // Parse U, V, ts from the response.
    EC_AFFINE U_affine, V_affine;
    EC_SCALAR ts;
    if (!cbs_get_point(cbs, group, &U_affine) ||
        !cbs_get_point(cbs, group, &V_affine) ||
        !scalar_from_cbs(cbs, group, &ts)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
      goto err;
    }

    // Check U and V are not the point at infinity.
    EC_JACOBIAN U_check, V_check;
    ec_affine_to_jacobian(group, &U_check, &U_affine);
    ec_affine_to_jacobian(group, &V_check, &V_affine);
    if (ec_GFp_simple_is_at_infinity(group, &U_check) ||
        ec_GFp_simple_is_at_infinity(group, &V_check)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
      goto err;
    }

    // Parse proof: C, e_vec[4], a_vec[4], a_d, a_rho, a_w
    EC_AFFINE C_affine;
    if (!cbs_get_point(cbs, group, &C_affine)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
      goto err;
    }

    EC_SCALAR branch_e[kNBuckets];
    EC_SCALAR branch_a[kNBuckets];
    for (size_t b = 0; b < kNBuckets; b++) {
      if (!scalar_from_cbs(cbs, group, &branch_e[b])) {
        OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
        goto err;
      }
    }
    for (size_t b = 0; b < kNBuckets; b++) {
      if (!scalar_from_cbs(cbs, group, &branch_a[b])) {
        OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
        goto err;
      }
    }
    EC_SCALAR a_d, a_rho, a_w;
    if (!scalar_from_cbs(cbs, group, &a_d) ||
        !scalar_from_cbs(cbs, group, &a_rho) ||
        !scalar_from_cbs(cbs, group, &a_w)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
      goto err;
    }

    // Compute e = sum(e_vec[i])
    EC_SCALAR e_sum;
    OPENSSL_memset(&e_sum, 0, sizeof(EC_SCALAR));
    for (size_t b = 0; b < kNBuckets; b++) {
      ec_scalar_add(group, &e_sum, &e_sum, &branch_e[b]);
    }

    // Recompute commitment points.
    EC_JACOBIAN U_j, V_j, C_j;
    ec_affine_to_jacobian(group, &U_j, &U_affine);
    ec_affine_to_jacobian(group, &V_j, &V_affine);
    ec_affine_to_jacobian(group, &C_j, &C_affine);

    EC_JACOBIAN C_y_j;
    ec_affine_to_jacobian(group, &C_y_j, &key->pub1);

    // Per-branch: C_vec[i] = a_vec[i]*H - e_vec[i]*(C - i*C_y)
    EC_JACOBIAN C_vec_jac[kNBuckets];
    for (size_t b = 0; b < kNBuckets; b++) {
      EC_SCALAR i_scalar;
      if (!make_small_scalar(group, &i_scalar, (uint8_t)b)) {
        goto err;
      }

      EC_JACOBIAN i_Cy;
      if (!ec_point_mul_scalar(group, &i_Cy, &C_y_j, &i_scalar)) {
        goto err;
      }
      EC_JACOBIAN neg_iCy = i_Cy;
      ec_GFp_simple_invert(group, &neg_iCy);
      EC_JACOBIAN C_minus_iCy;
      group->meth->add(group, &C_minus_iCy, &C_j, &neg_iCy);

      EC_JACOBIAN aiH;
      if (!ec_point_mul_scalar(group, &aiH, &method->h, &branch_a[b])) {
        goto err;
      }
      EC_SCALAR neg_ei;
      ec_scalar_neg(group, &neg_ei, &branch_e[b]);
      EC_JACOBIAN ei_part;
      if (!ec_point_mul_scalar(group, &ei_part, &C_minus_iCy, &neg_ei)) {
        goto err;
      }
      group->meth->add(group, &C_vec_jac[b], &aiH, &ei_part);
    }

    // Global verification:
    //   C_d   = a_d * U + e * G
    //   C_rho = a_d * V + a_rho * H + e*(C_x + C + ts*Z + T)
    //   C_w   = a_d * V + a_w * G + e * T

    // C_d = a_d * U + e * G
    EC_JACOBIAN C_d_jac;
    {
      EC_JACOBIAN adU, eG;
      if (!ec_point_mul_scalar(group, &adU, &U_j, &a_d) ||
          !ec_point_mul_scalar_base(group, &eG, &e_sum)) {
        goto err;
      }
      group->meth->add(group, &C_d_jac, &adU, &eG);
    }

    // C_rho = a_d * V + a_rho * H + e*(C_x + C + ts*Z + T)
    EC_JACOBIAN C_rho_jac;
    {
      EC_JACOBIAN adV, arhoH;
      if (!ec_point_mul_scalar(group, &adV, &V_j, &a_d) ||
          !ec_point_mul_scalar(group, &arhoH, &method->h, &a_rho)) {
        goto err;
      }

      // C_x + C + ts*Z + T
      EC_JACOBIAN C_x_j, Z_j, T_j;
      ec_affine_to_jacobian(group, &C_x_j, &key->pub0);
      ec_affine_to_jacobian(group, &Z_j, &key->pubs);
      ec_affine_to_jacobian(group, &T_j, &pretoken->Tp);
      EC_JACOBIAN tsZ;
      if (!ec_point_mul_scalar(group, &tsZ, &Z_j, &ts)) {
        goto err;
      }
      EC_JACOBIAN sum_points;
      group->meth->add(group, &sum_points, &C_x_j, &C_j);
      group->meth->add(group, &sum_points, &sum_points, &tsZ);
      group->meth->add(group, &sum_points, &sum_points, &T_j);

      EC_JACOBIAN e_sum_points;
      if (!ec_point_mul_scalar(group, &e_sum_points, &sum_points, &e_sum)) {
        goto err;
      }

      group->meth->add(group, &C_rho_jac, &adV, &arhoH);
      group->meth->add(group, &C_rho_jac, &C_rho_jac, &e_sum_points);
    }

    // C_w = a_d * V + a_w * G + e * T
    EC_JACOBIAN C_w_jac;
    {
      EC_JACOBIAN adV, awG;
      if (!ec_point_mul_scalar(group, &adV, &V_j, &a_d) ||
          !ec_point_mul_scalar_base(group, &awG, &a_w)) {
        goto err;
      }
      EC_JACOBIAN T_j;
      ec_affine_to_jacobian(group, &T_j, &pretoken->Tp);
      EC_JACOBIAN eT;
      if (!ec_point_mul_scalar(group, &eT, &T_j, &e_sum)) {
        goto err;
      }
      group->meth->add(group, &C_w_jac, &adV, &awG);
      group->meth->add(group, &C_w_jac, &C_w_jac, &eT);
    }

    // Convert all to affine.
    EC_JACOBIAN all_jacs[kNBuckets + 3];
    for (size_t b = 0; b < kNBuckets; b++) {
      all_jacs[b] = C_vec_jac[b];
    }
    all_jacs[kNBuckets] = C_d_jac;
    all_jacs[kNBuckets + 1] = C_rho_jac;
    all_jacs[kNBuckets + 2] = C_w_jac;

    EC_AFFINE all_affs[kNBuckets + 3];
    if (!ec_jacobian_to_affine_serial(group, all_affs, all_jacs,
                                     kNBuckets + 3)) {
      goto err;
    }

    // Recompute challenge.
    EC_SCALAR challenge;
    if (!hash_issuance_transcript(method, &challenge, &G_affine, &H_affine,
                                  &key->pub0, &key->pub1, &key->pubs,
                                  &U_affine, &V_affine, &ts, &pretoken->Tp,
                                  &C_affine, all_affs, kNBuckets,
                                  &all_affs[kNBuckets],
                                  &all_affs[kNBuckets + 1],
                                  &all_affs[kNBuckets + 2])) {
      goto err;
    }

    if (!ec_scalar_equal_vartime(group, &e_sum, &challenge)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_INVALID_PROOF);
      goto err;
    }

    // Unblind the token: P = c*U, Q = c*(V - r*U)
    EC_SCALAR c;
    if (!ec_random_nonzero_scalar(group, &c, kDefaultAdditionalData)) {
      goto err;
    }

    EC_JACOBIAN rU;
    if (!ec_point_mul_scalar(group, &rU, &U_j, &pretoken->r)) {
      goto err;
    }
    EC_JACOBIAN neg_rU = rU;
    ec_GFp_simple_invert(group, &neg_rU);
    EC_JACOBIAN V_minus_rU;
    group->meth->add(group, &V_minus_rU, &V_j, &neg_rU);

    EC_JACOBIAN P_j, Q_j;
    if (!ec_point_mul_scalar(group, &P_j, &U_j, &c) ||
        !ec_point_mul_scalar(group, &Q_j, &V_minus_rU, &c)) {
      goto err;
    }

    EC_JACOBIAN pq_jacs[2] = {P_j, Q_j};
    EC_AFFINE pq_affs[2];
    if (!ec_jacobian_to_affine_serial(group, pq_affs, pq_jacs, 2)) {
      goto err;
    }

    // t = tc + ts
    EC_SCALAR tc, t;
    size_t scalar_len = BN_num_bytes(EC_GROUP_get0_order(group));
    if (!ec_scalar_from_bytes(group, &tc, pretoken->salt, scalar_len)) {
      goto err;
    }
    ec_scalar_add(group, &t, &tc, &ts);

    // Serialize token: t (32B) || P (33B) || Q (33B) = 98 bytes
    CBB token_cbb;
    size_t point_len = ec_point_byte_len(group, POINT_CONVERSION_COMPRESSED);
    if (!CBB_init(&token_cbb, 4 + scalar_len + 2 * point_len) ||
        !CBB_add_u32(&token_cbb, key_id) ||
        !scalar_to_cbb(&token_cbb, group, &t) ||
        !point_to_cbb(&token_cbb, group, &pq_affs[0]) ||
        !point_to_cbb(&token_cbb, group, &pq_affs[1]) ||
        !CBB_flush(&token_cbb)) {
      CBB_cleanup(&token_cbb);
      goto err;
    }

    TRUST_TOKEN *token =
        TRUST_TOKEN_new(CBB_data(&token_cbb), CBB_len(&token_cbb));
    CBB_cleanup(&token_cbb);
    if (token == nullptr || !sk_TRUST_TOKEN_push(ret, token)) {
      TRUST_TOKEN_free(token);
      goto err;
    }
  }

  ok = 1;

err:
  if (!ok) {
    sk_TRUST_TOKEN_pop_free(ret, TRUST_TOKEN_free);
    ret = nullptr;
  }
  return ret;
}

static int athm_read(const ATHM_METHOD *method,
                      const TRUST_TOKEN_ISSUER_KEY *key,
                      uint8_t out_nonce[TRUST_TOKEN_NONCE_SIZE],
                      uint8_t *out_private_metadata, const uint8_t *token,
                      size_t token_len, int include_message,
                      const uint8_t *msg, size_t msg_len) {
  const EC_GROUP *group = method->group;
  CBS cbs;
  CBS_init(&cbs, token, token_len);

  // Parse token: t (scalar) || P (compressed point) || Q (compressed point)
  EC_SCALAR t;
  EC_AFFINE P, Q;
  if (!scalar_from_cbs(&cbs, group, &t) ||
      !cbs_get_point(&cbs, group, &P) ||
      !cbs_get_point(&cbs, group, &Q) ||
      CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_INVALID_TOKEN);
    return 0;
  }

  // Check P and Q are not the point at infinity.
  EC_JACOBIAN P_j, Q_j;
  ec_affine_to_jacobian(group, &P_j, &P);
  ec_affine_to_jacobian(group, &Q_j, &Q);

  if (ec_GFp_simple_is_at_infinity(group, &P_j) ||
      ec_GFp_simple_is_at_infinity(group, &Q_j)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_INVALID_TOKEN);
    return 0;
  }

  // For each bucket i in [0, nBuckets) check if Q == (x + t*z + i*y)*P
  crypto_word_t found_count = 0;
  uint8_t found_metadata = 0;
  for (size_t bucket = 0; bucket < kNBuckets; bucket++) {
    EC_SCALAR w, tmp_s;
    EC_SCALAR t_mont;
    ec_scalar_to_montgomery(group, &t_mont, &t);
    ec_scalar_mul_montgomery(group, &tmp_s, &key->xs, &t_mont);
    ec_scalar_add(group, &w, &key->x0, &tmp_s);

    EC_SCALAR bucket_scalar;
    if (!make_small_scalar(group, &bucket_scalar, (uint8_t)bucket)) {
      return 0;
    }
    EC_SCALAR bucket_mont;
    ec_scalar_to_montgomery(group, &bucket_mont, &bucket_scalar);
    ec_scalar_mul_montgomery(group, &tmp_s, &key->y0, &bucket_mont);
    ec_scalar_add(group, &w, &w, &tmp_s);

    EC_JACOBIAN Q_check;
    if (!ec_point_mul_scalar(group, &Q_check, &P_j, &w)) {
      return 0;
    }

    crypto_word_t match = constant_time_eq_w(
        ec_affine_jacobian_equal(group, &Q, &Q_check), 1);
    found_count = constant_time_select_w(match, found_count + 1, found_count);
    found_metadata = constant_time_select_8(match, (uint8_t)bucket,
                                            found_metadata);
  }

  if (found_count != 1) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_BAD_VALIDITY_CHECK);
    return 0;
  }

  *out_private_metadata = found_metadata;

  SHA512_CTX hash_ctx;
  SHA512_Init(&hash_ctx);
  SHA512_Update(&hash_ctx, token, token_len);
  if (include_message) {
    SHA512_Update(&hash_ctx, msg, msg_len);
  }
  SHA512_Final(out_nonce, &hash_ctx);

  return 1;
}


// athm_compute_h_from_deployment_id computes H for a given deployment_id.
int bssl::athm_compute_h_from_deployment_id(const EC_GROUP *group,
                                            EC_JACOBIAN *out_h,
                                            const uint8_t *deployment_id,
                                            size_t deployment_id_len) {
  static const char kPrefix[] = "HashToGroup-ATHMV1-P256-4-";
  static const char kSuffix[] = "generatorH";
  static const uint8_t kGeneratorGCompressed[] = {
      0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
      0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
      0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96};

  CBB cbb;
  CBB_zero(&cbb);
  uint8_t *dst = nullptr;
  size_t dst_len;
  if (!CBB_init(&cbb, 0) ||
      !CBB_add_bytes(&cbb, reinterpret_cast<const uint8_t *>(kPrefix),
                     sizeof(kPrefix) - 1) ||
      !CBB_add_bytes(&cbb, deployment_id, deployment_id_len) ||
      !CBB_add_bytes(&cbb, reinterpret_cast<const uint8_t *>(kSuffix),
                     sizeof(kSuffix) - 1) ||
      !CBB_finish(&cbb, &dst, &dst_len)) {
    CBB_cleanup(&cbb);
    return 0;
  }

  int ok = ec_hash_to_curve_p256_xmd_sha256_sswu(
      group, out_h, dst, dst_len, kGeneratorGCompressed,
      sizeof(kGeneratorGCompressed));
  OPENSSL_free(dst);
  return ok;
}

// athm_get_method resolves ATHM_METHOD from method_data.
static int athm_get_method(ATHM_METHOD *out, const void *method_data) {
  if (!method_data) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DEPLOYMENT_ID_REQUIRED);
    return 0;
  }
  const ATHM_CONTEXT_DATA *data =
      static_cast<const ATHM_CONTEXT_DATA *>(method_data);
  out->group = EC_group_p256();
  out->h = data->h;
  out->context_string = nullptr;
  out->context_string_len = 0;
  if (!build_context_string(&out->context_string, &out->context_string_len,
                            data->deployment_id, data->deployment_id_len)) {
    return 0;
  }
  return 1;
}

// ATHM v1 method initialization (for the static default with empty
// deployment_id).

static int athm_v1_ok = 0;
static ATHM_METHOD athm_v1_method;
static CRYPTO_once_t athm_v1_method_once = CRYPTO_ONCE_INIT;

static void athm_v1_init_method_impl() {
  static const uint8_t kDST[] = "HashToGroup-ATHMV1-P256-4-generatorH";
  static const uint8_t kGeneratorGCompressed[] = {
      0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
      0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
      0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96};

  const EC_GROUP *group = EC_group_p256();
  EC_JACOBIAN h_j;
  if (!ec_hash_to_curve_p256_xmd_sha256_sswu(
          group, &h_j, kDST, sizeof(kDST) - 1, kGeneratorGCompressed,
          sizeof(kGeneratorGCompressed))) {
    return;
  }

  // Empty deployment_id for the static default.
  athm_v1_ok = athm_init_method(&athm_v1_method, group, &h_j, nullptr, 0);
}

static int athm_v1_init_method() {
  CRYPTO_once(&athm_v1_method_once, athm_v1_init_method_impl);
  if (!athm_v1_ok) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_INTERNAL_ERROR);
    return 0;
  }
  return 1;
}

int bssl::athm_v1_generate_key(CBB *out_private, CBB *out_public,
                                const void *method_data) {
  ATHM_METHOD m;
  if (!athm_get_method(&m, method_data)) {
    return 0;
  }
  int ret = athm_generate_key(&m, out_private, out_public);
  athm_method_cleanup(&m);
  return ret;
}

int bssl::athm_v1_derive_key_from_secret(CBB *out_private, CBB *out_public,
                                          const uint8_t *secret,
                                          size_t secret_len,
                                          const void *method_data) {
  ATHM_METHOD m;
  if (!athm_get_method(&m, method_data)) {
    return 0;
  }
  int ret = athm_derive_key_from_secret(&m, out_private, out_public, secret,
                                         secret_len);
  athm_method_cleanup(&m);
  return ret;
}

int bssl::athm_v1_client_key_from_bytes(TRUST_TOKEN_CLIENT_KEY *key,
                                         const uint8_t *in, size_t len,
                                         const void *method_data) {
  ATHM_METHOD m;
  if (!athm_get_method(&m, method_data)) {
    return 0;
  }
  int ret = athm_client_key_from_bytes(&m, key, in, len);
  athm_method_cleanup(&m);
  return ret;
}

int bssl::athm_v1_issuer_key_from_bytes(TRUST_TOKEN_ISSUER_KEY *key,
                                         const uint8_t *in, size_t len,
                                         const void *method_data) {
  ATHM_METHOD m;
  if (!athm_get_method(&m, method_data)) {
    return 0;
  }
  int ret = athm_issuer_key_from_bytes(&m, key, in, len);
  athm_method_cleanup(&m);
  return ret;
}

STACK_OF(TRUST_TOKEN_PRETOKEN) *bssl::athm_v1_blind(
    CBB *cbb, size_t count, int include_message, const uint8_t *msg,
    size_t msg_len, const TRUST_TOKEN_CLIENT_KEY *key) {
  if (!athm_v1_init_method()) {
    return nullptr;
  }
  return athm_blind(&athm_v1_method, cbb, count, include_message, msg, msg_len,
                    key);
}

int bssl::athm_v1_sign(const TRUST_TOKEN_ISSUER_KEY *key, CBB *cbb, CBS *cbs,
                        size_t num_requested, size_t num_to_issue,
                        uint8_t private_metadata,
                        const void *method_data) {
  ATHM_METHOD m;
  if (!athm_get_method(&m, method_data)) {
    return 0;
  }
  int ret = athm_sign(&m, key, cbb, cbs, num_requested, num_to_issue,
                       private_metadata);
  athm_method_cleanup(&m);
  return ret;
}

STACK_OF(TRUST_TOKEN) *bssl::athm_v1_unblind(
    const TRUST_TOKEN_CLIENT_KEY *key,
    const STACK_OF(TRUST_TOKEN_PRETOKEN) *pretokens, CBS *cbs, size_t count,
    uint32_t key_id, const void *method_data) {
  ATHM_METHOD m;
  if (!athm_get_method(&m, method_data)) {
    return nullptr;
  }
  STACK_OF(TRUST_TOKEN) *ret =
      athm_unblind(&m, key, pretokens, cbs, count, key_id);
  athm_method_cleanup(&m);
  return ret;
}

int bssl::athm_v1_read(const TRUST_TOKEN_ISSUER_KEY *key,
                        uint8_t out_nonce[TRUST_TOKEN_NONCE_SIZE],
                        uint8_t *out_private_metadata, const uint8_t *token,
                        size_t token_len, int include_message,
                        const uint8_t *msg, size_t msg_len) {
  if (!athm_v1_init_method()) {
    return 0;
  }
  return athm_read(&athm_v1_method, key, out_nonce, out_private_metadata, token,
                    token_len, include_message, msg, msg_len);
}

int bssl::athm_v1_get_h_for_testing(uint8_t out[65]) {
  if (!athm_v1_init_method()) {
    return 0;
  }
  EC_AFFINE h;
  return ec_jacobian_to_affine(athm_v1_method.group, &h, &athm_v1_method.h) &&
         ec_point_to_bytes(athm_v1_method.group, &h,
                           POINT_CONVERSION_UNCOMPRESSED, out, 65) == 65;
}
