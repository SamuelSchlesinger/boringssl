// Copyright 2020 The BoringSSL Authors
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

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <algorithm>
#include <limits>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <openssl/bytestring.h>
#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/sha2.h>
#include <openssl/trust_token.h>

#include "../ec/internal.h"
#include "../fipsmodule/ec/internal.h"
#include "../internal.h"
#include "../test/test_util.h"
#include "internal.h"


BSSL_NAMESPACE_BEGIN

namespace {

const uint8_t kMessage[] = "MSG";

TEST(TrustTokenTest, KeyGenExp1) {
  uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_len, pub_key_len;
  ASSERT_TRUE(TRUST_TOKEN_generate_key(
      TRUST_TOKEN_experiment_v1(), priv_key, &priv_key_len,
      TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, pub_key, &pub_key_len,
      TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0x0001));
  ASSERT_EQ(292u, priv_key_len);
  ASSERT_EQ(301u, pub_key_len);

  const uint8_t kKeygenSecret[] = "SEED";
  ASSERT_TRUE(TRUST_TOKEN_derive_key_from_secret(
      TRUST_TOKEN_experiment_v1(), priv_key, &priv_key_len,
      TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, pub_key, &pub_key_len,
      TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0x0001, kKeygenSecret,
      sizeof(kKeygenSecret) - 1));

  const uint8_t kExpectedPriv[] = {
      0x00, 0x00, 0x00, 0x01, 0x98, 0xaa, 0x32, 0xfc, 0x5f, 0x83, 0x35, 0xea,
      0x57, 0x4f, 0x9e, 0x61, 0x48, 0x6e, 0x89, 0x9d, 0x3d, 0xaa, 0x38, 0x5d,
      0xd0, 0x06, 0x96, 0x62, 0xe8, 0x0b, 0xd6, 0x5f, 0x12, 0xa4, 0xcc, 0xa9,
      0xb5, 0x20, 0x1b, 0x13, 0x8c, 0x1c, 0xaf, 0x36, 0x1b, 0xab, 0x0c, 0xc6,
      0xac, 0x38, 0xae, 0x96, 0x3d, 0x14, 0x9d, 0xb8, 0x8d, 0xf4, 0x7f, 0xe2,
      0x7d, 0xeb, 0x17, 0xc2, 0xbc, 0x63, 0x42, 0x93, 0x94, 0xe4, 0x97, 0xbf,
      0x97, 0xea, 0x02, 0x40, 0xac, 0xb6, 0xa5, 0x03, 0x4c, 0x6b, 0x4c, 0xb8,
      0x8c, 0xf4, 0x66, 0x1b, 0x4e, 0x02, 0x45, 0xf9, 0xcd, 0xb6, 0x0f, 0x59,
      0x09, 0x21, 0x03, 0x7e, 0x92, 0x1f, 0x3f, 0x40, 0x83, 0x50, 0xe3, 0xdc,
      0x9e, 0x6f, 0x65, 0xc5, 0xbd, 0x2c, 0x7d, 0xab, 0x74, 0x49, 0xc8, 0xa2,
      0x3c, 0xab, 0xcb, 0x4d, 0x63, 0x73, 0x81, 0x2b, 0xb2, 0x1e, 0x00, 0x8f,
      0x00, 0xb8, 0xd8, 0xb4, 0x5d, 0xc4, 0x3f, 0x3d, 0xa8, 0x4f, 0x4c, 0x72,
      0x0e, 0x20, 0x17, 0x4b, 0xac, 0x14, 0x8f, 0xb2, 0xa5, 0x20, 0x41, 0x2b,
      0xf7, 0x62, 0x25, 0x6a, 0xd6, 0x41, 0x26, 0x62, 0x10, 0xc1, 0xbc, 0x42,
      0xac, 0x54, 0x1b, 0x75, 0x05, 0xd6, 0x53, 0xb1, 0x7b, 0x84, 0x6a, 0x7b,
      0x5b, 0x2a, 0x34, 0x6e, 0x43, 0x4b, 0x43, 0xcc, 0x6c, 0xdb, 0x1d, 0x02,
      0x34, 0x7f, 0xd1, 0xe8, 0xfd, 0x42, 0x2c, 0xd9, 0x14, 0xdb, 0xd6, 0xf4,
      0xad, 0xb5, 0xe4, 0xac, 0xdd, 0x7e, 0xb5, 0x4c, 0x3f, 0x59, 0x24, 0xfa,
      0x04, 0xd9, 0xb6, 0xd2, 0xb7, 0x7d, 0xf1, 0xfa, 0x13, 0xc0, 0x4d, 0xd5,
      0xca, 0x3a, 0x4e, 0xa8, 0xdd, 0xa9, 0xfc, 0xcb, 0x06, 0xb2, 0xde, 0x4b,
      0x2a, 0x86, 0xbb, 0x0d, 0x41, 0xb6, 0x3d, 0xfb, 0x49, 0xc8, 0xdf, 0x9a,
      0x48, 0xe5, 0x68, 0x8a, 0xfc, 0x86, 0x9c, 0x79, 0x5a, 0x79, 0xc1, 0x09,
      0x33, 0x53, 0xdc, 0x3d, 0xe9, 0x93, 0x7c, 0x5b, 0x72, 0xf7, 0xa0, 0x8a,
      0x1f, 0x07, 0x6c, 0x38, 0x3c, 0x99, 0x0b, 0xe4, 0x4e, 0xa4, 0xbd, 0x41,
      0x1f, 0x83, 0xa6, 0xd3
  };
  ASSERT_EQ(Bytes(kExpectedPriv, sizeof(kExpectedPriv)),
            Bytes(priv_key, priv_key_len));

  const uint8_t kExpectedPub[] = {
      0x00, 0x00, 0x00, 0x01, 0x00, 0x61, 0x04, 0x5e, 0x06, 0x6b, 0x7b, 0xfd,
      0x54, 0x01, 0xe0, 0xd2, 0xb5, 0x12, 0xce, 0x48, 0x16, 0x66, 0xb2, 0xdf,
      0xfd, 0xa8, 0x38, 0x7c, 0x1f, 0x45, 0x1a, 0xb8, 0x21, 0x52, 0x17, 0x25,
      0xbb, 0x0b, 0x00, 0xd4, 0xa1, 0xbc, 0x28, 0xd9, 0x08, 0x36, 0x98, 0xb2,
      0x17, 0xd3, 0xb5, 0xad, 0xb6, 0x4e, 0x03, 0x5f, 0xd3, 0x66, 0x2c, 0x58,
      0x1c, 0xcc, 0xc6, 0x23, 0xa4, 0xf9, 0xa2, 0x7e, 0xb0, 0xe4, 0xd3, 0x95,
      0x41, 0x6f, 0xba, 0x23, 0x4a, 0x82, 0x93, 0x29, 0x73, 0x75, 0x38, 0x85,
      0x64, 0x9c, 0xaa, 0x12, 0x6d, 0x7d, 0xcd, 0x52, 0x02, 0x91, 0x9f, 0xa9,
      0xee, 0x4b, 0xfd, 0x68, 0x97, 0x40, 0xdc, 0x00, 0x61, 0x04, 0x14, 0x16,
      0x39, 0xf9, 0x63, 0x66, 0x94, 0x03, 0xfa, 0x0b, 0xbf, 0xca, 0x5a, 0x39,
      0x9f, 0x27, 0x5b, 0x3f, 0x69, 0x7a, 0xc9, 0xf7, 0x25, 0x7c, 0x84, 0x9e,
      0x1d, 0x61, 0x5a, 0x24, 0x53, 0xf2, 0x4a, 0x9d, 0xe9, 0x05, 0x53, 0xfd,
      0x12, 0x01, 0x2d, 0x9a, 0x69, 0x50, 0x74, 0x82, 0xa3, 0x45, 0x73, 0xdc,
      0x34, 0x36, 0x31, 0x44, 0x07, 0x0c, 0xda, 0x13, 0xbe, 0x94, 0x37, 0x65,
      0xa0, 0xab, 0x16, 0x52, 0x90, 0xe5, 0x8a, 0x03, 0xe5, 0x98, 0x79, 0x14,
      0x79, 0xd5, 0x17, 0xee, 0xd4, 0xb8, 0xda, 0x77, 0x76, 0x03, 0x20, 0x2a,
      0x7e, 0x3b, 0x76, 0x0b, 0x23, 0xb7, 0x72, 0x77, 0xb2, 0xeb, 0x00, 0x61,
      0x04, 0x68, 0x18, 0x4d, 0x23, 0x23, 0xf4, 0x45, 0xb8, 0x81, 0x0d, 0xa4,
      0x5d, 0x0b, 0x9e, 0x08, 0xfb, 0x45, 0xfb, 0x96, 0x29, 0x43, 0x2f, 0xab,
      0x93, 0x04, 0x4c, 0x04, 0xb6, 0x5e, 0x27, 0xf5, 0x39, 0x66, 0x94, 0x15,
      0x1d, 0xb1, 0x1c, 0x7c, 0x27, 0x6f, 0xa5, 0x19, 0x0c, 0x30, 0x12, 0xcc,
      0x77, 0x7f, 0x10, 0xa9, 0x7c, 0xe4, 0x08, 0x77, 0x3c, 0xd3, 0x6f, 0xa4,
      0xf4, 0xaf, 0xf1, 0x9d, 0x14, 0x1d, 0xd0, 0x02, 0x33, 0x50, 0x55, 0x00,
      0x6a, 0x47, 0x96, 0xe1, 0x8b, 0x4e, 0x44, 0x41, 0xad, 0xb3, 0xea, 0x0d,
      0x0d, 0xd5, 0x73, 0x8e, 0x62, 0x67, 0x8a, 0xb4, 0xe7, 0x5d, 0x17, 0xa9,
      0x24};
  ASSERT_EQ(Bytes(kExpectedPub, sizeof(kExpectedPub)),
            Bytes(pub_key, pub_key_len));
}

TEST(TrustTokenTest, KeyGenExp2VOPRF) {
  uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_len, pub_key_len;
  ASSERT_TRUE(TRUST_TOKEN_generate_key(
      TRUST_TOKEN_experiment_v2_voprf(), priv_key, &priv_key_len,
      TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, pub_key, &pub_key_len,
      TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0x0001));
  ASSERT_EQ(52u, priv_key_len);
  ASSERT_EQ(101u, pub_key_len);

  const uint8_t kKeygenSecret[] = "SEED";
  ASSERT_TRUE(TRUST_TOKEN_derive_key_from_secret(
      TRUST_TOKEN_experiment_v2_voprf(), priv_key, &priv_key_len,
      TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, pub_key, &pub_key_len,
      TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0x0001, kKeygenSecret,
      sizeof(kKeygenSecret) - 1));

  const uint8_t kExpectedPriv[] = {
      0x00, 0x00, 0x00, 0x01, 0x0b, 0xe2, 0xc4, 0x73, 0x92, 0xe7, 0xf8,
      0x3e, 0xba, 0xab, 0x85, 0xa7, 0x77, 0xd7, 0x0a, 0x02, 0xc5, 0x36,
      0xfe, 0x62, 0xa3, 0xca, 0x01, 0x75, 0xc7, 0x62, 0x19, 0xc7, 0xf0,
      0x30, 0xc5, 0x14, 0x60, 0x13, 0x97, 0x4f, 0x63, 0x05, 0x37, 0x92,
      0x7b, 0x76, 0x8e, 0x9f, 0xd0, 0x1a, 0x74, 0x44
  };
  ASSERT_EQ(Bytes(kExpectedPriv, sizeof(kExpectedPriv)),
            Bytes(priv_key, priv_key_len));

  const uint8_t kExpectedPub[] = {
      0x00, 0x00, 0x00, 0x01, 0x04, 0x2c, 0x9c, 0x11, 0xc1, 0xe5, 0x52, 0x59,
      0x0b, 0x6d, 0x88, 0x8b, 0x6e, 0x28, 0xe8, 0xc5, 0xa3, 0xbe, 0x48, 0x18,
      0xf7, 0x1d, 0x31, 0xcf, 0xa2, 0x6e, 0x2a, 0xd6, 0xcb, 0x83, 0x26, 0x04,
      0xbd, 0x93, 0x67, 0xe4, 0x53, 0xf6, 0x11, 0x7d, 0x45, 0xe9, 0xfe, 0x27,
      0x33, 0x90, 0xdb, 0x1b, 0xfc, 0x9b, 0x31, 0x4d, 0x39, 0x1f, 0x1f, 0x8c,
      0x43, 0x06, 0x70, 0x2c, 0x84, 0xdc, 0x23, 0x18, 0xc7, 0x6a, 0x58, 0xcf,
      0x9e, 0xc1, 0xfa, 0xf2, 0x30, 0xdd, 0xad, 0x62, 0x24, 0xde, 0x11, 0xc1,
      0xba, 0x8d, 0xc3, 0x4f, 0xfb, 0xe5, 0xa5, 0xd4, 0x37, 0xba, 0x3b, 0x70,
      0xc0, 0xc3, 0xef, 0x20, 0x43
  };
  ASSERT_EQ(Bytes(kExpectedPub, sizeof(kExpectedPub)),
            Bytes(pub_key, pub_key_len));
}

TEST(TrustTokenTest, KeyGenExp2PMB) {
  uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_len, pub_key_len;
  ASSERT_TRUE(TRUST_TOKEN_generate_key(
      TRUST_TOKEN_experiment_v2_pmb(), priv_key, &priv_key_len,
      TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, pub_key, &pub_key_len,
      TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0x0001));
  ASSERT_EQ(292u, priv_key_len);
  ASSERT_EQ(295u, pub_key_len);

  const uint8_t kKeygenSecret[] = "SEED";
  ASSERT_TRUE(TRUST_TOKEN_derive_key_from_secret(
      TRUST_TOKEN_experiment_v2_pmb(), priv_key, &priv_key_len,
      TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, pub_key, &pub_key_len,
      TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0x0001, kKeygenSecret,
      sizeof(kKeygenSecret) - 1));

  const uint8_t kExpectedPriv[] = {
      0x00, 0x00, 0x00, 0x01, 0x1b, 0x74, 0xdc, 0xf0, 0xa9, 0xa7, 0x6c, 0xfb,
      0x41, 0xef, 0xfa, 0x65, 0x52, 0xc9, 0x86, 0x4e, 0xfb, 0x16, 0x9d, 0xea,
      0x62, 0x3f, 0x47, 0xab, 0x1f, 0x1b, 0x05, 0xf2, 0x4f, 0x05, 0xfe, 0x64,
      0xb7, 0xe8, 0xcd, 0x2a, 0x10, 0xfa, 0xa2, 0x48, 0x3f, 0x0e, 0x8b, 0x94,
      0x39, 0xf1, 0xe7, 0x53, 0xe9, 0x50, 0x29, 0xe2, 0xb7, 0x0e, 0xc0, 0x94,
      0xa9, 0xd3, 0xef, 0x64, 0x10, 0x1d, 0x08, 0xd0, 0x60, 0xcb, 0x6d, 0x97,
      0x68, 0xc7, 0x04, 0x92, 0x07, 0xb2, 0x22, 0x83, 0xf7, 0xd9, 0x9b, 0x2c,
      0xf2, 0x52, 0x34, 0x0c, 0x42, 0x31, 0x47, 0x41, 0x19, 0xb9, 0xee, 0xfc,
      0x46, 0xbd, 0x14, 0xce, 0x42, 0xd7, 0x43, 0xc8, 0x32, 0x3b, 0x24, 0xed,
      0xdc, 0x69, 0xa3, 0x8e, 0x29, 0x01, 0xbe, 0xae, 0x24, 0x39, 0x14, 0xa7,
      0x52, 0xe5, 0xd5, 0xff, 0x9a, 0xc4, 0x15, 0x79, 0x29, 0x4c, 0x9b, 0x4e,
      0xfc, 0x61, 0xf2, 0x12, 0x6f, 0x4f, 0xd3, 0x96, 0x28, 0xb0, 0x79, 0xf0,
      0x4e, 0x6e, 0x7d, 0x56, 0x19, 0x1b, 0xc2, 0xd7, 0xf9, 0x3a, 0x58, 0x06,
      0xe5, 0xec, 0xa4, 0x33, 0x14, 0x1c, 0x78, 0x0c, 0x83, 0x94, 0x34, 0x22,
      0x5a, 0x8e, 0x2e, 0xa1, 0x72, 0x4a, 0x03, 0x35, 0xfe, 0x46, 0x92, 0x41,
      0x6b, 0xe6, 0x4b, 0x3f, 0xf0, 0xe7, 0x0b, 0xb5, 0xf3, 0x66, 0x6c, 0xc6,
      0x14, 0xcf, 0xce, 0x32, 0x0a, 0x2c, 0x28, 0xba, 0x4e, 0xb9, 0x75, 0x4a,
      0xa9, 0x2d, 0xb0, 0x8c, 0xd0, 0x62, 0x52, 0x29, 0x1f, 0x12, 0xfd, 0xfb,
      0xd3, 0x2a, 0x36, 0x0f, 0x89, 0x32, 0x86, 0x25, 0x56, 0xb9, 0xe7, 0x3c,
      0xeb, 0xb4, 0x84, 0x41, 0x2b, 0xa8, 0xf3, 0xa5, 0x3d, 0xfe, 0x56, 0x94,
      0x5b, 0x74, 0xb3, 0x5b, 0x27, 0x3f, 0xe7, 0xcf, 0xe4, 0xf8, 0x15, 0x95,
      0x2a, 0xd2, 0x5f, 0x92, 0xb4, 0x6a, 0x89, 0xa5, 0x54, 0xbd, 0x27, 0x5e,
      0xeb, 0x43, 0x07, 0x9b, 0x2b, 0x8b, 0x22, 0x59, 0x13, 0x4b, 0x9c, 0x56,
      0xd8, 0x63, 0xd9, 0xe6, 0x85, 0x15, 0x2c, 0x82, 0x52, 0x40, 0x8f, 0xb1,
      0xe7, 0x56, 0x07, 0x98
  };
  ASSERT_EQ(Bytes(kExpectedPriv, sizeof(kExpectedPriv)),
            Bytes(priv_key, priv_key_len));

  const uint8_t kExpectedPub[] = {
      0x00, 0x00, 0x00, 0x01, 0x04, 0x48, 0xb1, 0x2d, 0xdd, 0x03, 0x32, 0xeb,
      0x93, 0x31, 0x3d, 0x59, 0x74, 0xf0, 0xcf, 0xaa, 0xa5, 0x39, 0x5f, 0x53,
      0xc4, 0x94, 0x98, 0xbe, 0x8f, 0x22, 0xd7, 0x30, 0xde, 0x1e, 0xb4, 0xf3,
      0x32, 0x23, 0x90, 0x0b, 0xa6, 0x37, 0x4a, 0x4b, 0x44, 0xb3, 0x26, 0x52,
      0x93, 0x7b, 0x4b, 0xa4, 0x79, 0xe8, 0x77, 0x6a, 0x19, 0x81, 0x2a, 0xdd,
      0x91, 0xfb, 0x90, 0x8b, 0x24, 0xb5, 0xbe, 0x20, 0x2e, 0xe8, 0xbc, 0xd3,
      0x83, 0x6c, 0xa8, 0xc5, 0xa1, 0x9a, 0x5b, 0x5e, 0x60, 0xda, 0x45, 0x2e,
      0x31, 0x7f, 0x54, 0x0e, 0x14, 0x40, 0xd2, 0x4d, 0x40, 0x2e, 0x21, 0x79,
      0xfc, 0x77, 0xdd, 0xc7, 0x2d, 0x04, 0xfe, 0xc6, 0xe3, 0xcf, 0x99, 0xef,
      0x88, 0xab, 0x76, 0x86, 0x16, 0x14, 0xed, 0x72, 0x35, 0xa7, 0x05, 0x13,
      0x9f, 0x2c, 0x53, 0xd5, 0xdf, 0x66, 0x75, 0x2e, 0x68, 0xdc, 0xd4, 0xc4,
      0x00, 0x36, 0x08, 0x6d, 0xb7, 0x15, 0xf7, 0xe5, 0x32, 0x59, 0x81, 0x16,
      0x57, 0xaa, 0x72, 0x06, 0xf0, 0xad, 0xd1, 0x85, 0xa0, 0x04, 0xd4, 0x11,
      0x95, 0x1d, 0xac, 0x0b, 0x25, 0xbe, 0x59, 0xa2, 0xb3, 0x30, 0xee, 0x97,
      0x07, 0x2a, 0x51, 0x15, 0xc1, 0x8d, 0xa8, 0xa6, 0x57, 0x9a, 0x4e, 0xbf,
      0xd7, 0x2d, 0x35, 0x07, 0x6b, 0xd6, 0xc9, 0x3c, 0xe4, 0xcf, 0x0b, 0x14,
      0x3e, 0x10, 0x51, 0x77, 0xd6, 0x84, 0x04, 0xbe, 0xd1, 0xd5, 0xa8, 0xf3,
      0x9d, 0x1d, 0x4f, 0xc1, 0xc9, 0xf1, 0x0c, 0x6d, 0xb6, 0xcb, 0xe2, 0x05,
      0x0b, 0x9c, 0x7a, 0x3a, 0x9a, 0x99, 0xe9, 0xa1, 0x93, 0xdc, 0x72, 0x2e,
      0xef, 0xf3, 0x8d, 0xb9, 0x7b, 0xb0, 0x19, 0x24, 0x95, 0x0d, 0x68, 0xa7,
      0xe0, 0xaa, 0x0b, 0xb1, 0xd1, 0xcc, 0x52, 0x14, 0xf9, 0x6c, 0x91, 0x59,
      0xe4, 0xe1, 0x9b, 0xf9, 0x12, 0x39, 0xb1, 0x79, 0xbb, 0x21, 0x92, 0x00,
      0xa4, 0x89, 0xf5, 0xbd, 0xd7, 0x89, 0x27, 0x40, 0xdc, 0xb1, 0x09, 0x38,
      0x63, 0x91, 0x8c, 0xa5, 0x27, 0x27, 0x97, 0x39, 0x35, 0xfa, 0x1a, 0x8a,
      0xa7, 0xe5, 0xc4, 0xd8, 0xbf, 0xe7, 0xbe
  };
  ASSERT_EQ(Bytes(kExpectedPub, sizeof(kExpectedPub)),
            Bytes(pub_key, pub_key_len));
}

// Test that H in |TRUST_TOKEN_experiment_v1| was computed correctly.
TEST(TrustTokenTest, HExp1) {
  const EC_GROUP *group = EC_group_p384();
  const uint8_t kHGen[] = "generator";
  const uint8_t kHLabel[] = "PMBTokens Experiment V1 HashH";

  bssl::UniquePtr<EC_POINT> expected_h(EC_POINT_new(group));
  ASSERT_TRUE(expected_h);
  ASSERT_TRUE(ec_hash_to_curve_p384_xmd_sha512_sswu_draft07(
      group, &expected_h->raw, kHLabel, sizeof(kHLabel), kHGen, sizeof(kHGen)));
  uint8_t expected_bytes[1 + 2 * EC_MAX_BYTES];
  size_t expected_len =
      EC_POINT_point2oct(group, expected_h.get(), POINT_CONVERSION_UNCOMPRESSED,
                         expected_bytes, sizeof(expected_bytes), nullptr);

  uint8_t h[97];
  ASSERT_TRUE(pmbtoken_exp1_get_h_for_testing(h));
  EXPECT_EQ(Bytes(h), Bytes(expected_bytes, expected_len));
}

// Test that H in |TRUST_TOKEN_experiment_v2_pmb| was computed correctly.
TEST(TrustTokenTest, HExp2) {
  const EC_GROUP *group = EC_group_p384();
  const uint8_t kHGen[] = "generator";
  const uint8_t kHLabel[] = "PMBTokens Experiment V2 HashH";

  bssl::UniquePtr<EC_POINT> expected_h(EC_POINT_new(group));
  ASSERT_TRUE(expected_h);
  ASSERT_TRUE(ec_hash_to_curve_p384_xmd_sha512_sswu_draft07(
      group, &expected_h->raw, kHLabel, sizeof(kHLabel), kHGen, sizeof(kHGen)));
  uint8_t expected_bytes[1 + 2 * EC_MAX_BYTES];
  size_t expected_len =
      EC_POINT_point2oct(group, expected_h.get(), POINT_CONVERSION_UNCOMPRESSED,
                         expected_bytes, sizeof(expected_bytes), nullptr);

  uint8_t h[97];
  ASSERT_TRUE(pmbtoken_exp2_get_h_for_testing(h));
  EXPECT_EQ(Bytes(h), Bytes(expected_bytes, expected_len));
}

// Test that H in |TRUST_TOKEN_pst_v1_pmb| was computed correctly.
TEST(TrustTokenTest, HPST1) {
  const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);
  ASSERT_TRUE(group);

  const uint8_t kHGen[] = "generator";
  const uint8_t kHLabel[] = "PMBTokens PST V1 HashH";

  bssl::UniquePtr<EC_POINT> expected_h(EC_POINT_new(group));
  ASSERT_TRUE(expected_h);
  ASSERT_TRUE(ec_hash_to_curve_p384_xmd_sha384_sswu(
      group, &expected_h->raw, kHLabel, sizeof(kHLabel), kHGen, sizeof(kHGen)));
  uint8_t expected_bytes[1 + 2 * EC_MAX_BYTES];
  size_t expected_len =
      EC_POINT_point2oct(group, expected_h.get(), POINT_CONVERSION_UNCOMPRESSED,
                         expected_bytes, sizeof(expected_bytes), nullptr);

  uint8_t h[97];
  ASSERT_TRUE(pmbtoken_pst1_get_h_for_testing(h));
  EXPECT_EQ(Bytes(h), Bytes(expected_bytes, expected_len));
}

static int ec_point_uncompressed_from_compressed(
    const EC_GROUP *group, uint8_t out[EC_MAX_UNCOMPRESSED], size_t *out_len,
    const uint8_t *in, size_t len) {
  bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group));
  if (!point ||
      !EC_POINT_oct2point(group, point.get(), in, len, nullptr)) {
    return 0;
  }

  *out_len =
      EC_POINT_point2oct(group, point.get(), POINT_CONVERSION_UNCOMPRESSED, out,
                         EC_MAX_UNCOMPRESSED, nullptr);
  return 1;
}

static bool setup_voprf_test_key(const EC_GROUP *group,
                                 TRUST_TOKEN_ISSUER_KEY *out) {
  static const uint8_t kPrivateKey[] = {
      0x05, 0x16, 0x46, 0xb9, 0xe6, 0xe7, 0xa7, 0x1a, 0xe2, 0x7c, 0x1e, 0x1d,
      0x0b, 0x87, 0xb4, 0x38, 0x1d, 0xb6, 0xd3, 0x59, 0x5e, 0xee, 0xb1, 0xad,
      0xb4, 0x15, 0x79, 0xad, 0xbf, 0x99, 0x2f, 0x42, 0x78, 0xf9, 0x01, 0x6e,
      0xaf, 0xc9, 0x44, 0xed, 0xaa, 0x2b, 0x43, 0x18, 0x35, 0x81, 0x77, 0x9d
  };

  static const uint8_t kPublicKey[] = {
      0x03, 0x1d, 0x68, 0x96, 0x86, 0xc6, 0x11, 0x99, 0x1b, 0x55,
      0xf1, 0xa1, 0xd8, 0xf4, 0x30, 0x5c, 0xcd, 0x6c, 0xb7, 0x19,
      0x44, 0x6f, 0x66, 0x0a, 0x30, 0xdb, 0x61, 0xb7, 0xaa, 0x87,
      0xb4, 0x6a, 0xcf, 0x59, 0xb7, 0xc0, 0xd4, 0xa9, 0x07, 0x7b,
      0x3d, 0xa2, 0x1c, 0x25, 0xdd, 0x48, 0x22, 0x29, 0xa0
  };

  if (!ec_scalar_from_bytes(group, &out->xs, kPrivateKey,
                            sizeof(kPrivateKey))) {
    return false;
  }

  bssl::UniquePtr<EC_POINT> pub(EC_POINT_new(group));
  return pub &&
         EC_POINT_oct2point(group, pub.get(), kPublicKey, sizeof(kPublicKey),
                            nullptr) &&
         ec_jacobian_to_affine(group, &out->pubs, &pub->raw);
}

TEST(TrustTokenTest, PSTV1VOPRFTestVector1) {
  const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);
  TRUST_TOKEN_ISSUER_KEY key;
  ASSERT_TRUE(setup_voprf_test_key(group, &key));

  static const uint8_t kBlindedElement[] = {
      0x02, 0xd3, 0x38, 0xc0, 0x5c, 0xbe, 0xcb, 0x82, 0xde, 0x13,
      0xd6, 0x70, 0x0f, 0x09, 0xcb, 0x61, 0x19, 0x05, 0x43, 0xa7,
      0xb7, 0xe2, 0xc6, 0xcd, 0x4f, 0xca, 0x56, 0x88, 0x7e, 0x56,
      0x4e, 0xa8, 0x26, 0x53, 0xb2, 0x7f, 0xda, 0xd3, 0x83, 0x99,
      0x5e, 0xa6, 0xd0, 0x2c, 0xf2, 0x6d, 0x0e, 0x24, 0xd9
  };

  static const uint8_t kEvaluatedElement[] = {
      0x02, 0xa7, 0xbb, 0xa5, 0x89, 0xb3, 0xe8, 0x67, 0x2a, 0xa1,
      0x9e, 0x8f, 0xd2, 0x58, 0xde, 0x2e, 0x6a, 0xae, 0x20, 0x10,
      0x1c, 0x8d, 0x76, 0x12, 0x46, 0xde, 0x97, 0xa6, 0xb5, 0xee,
      0x9c, 0xf1, 0x05, 0xfe, 0xbc, 0xe4, 0x32, 0x7a, 0x32, 0x62,
      0x55, 0xa3, 0xc6, 0x04, 0xf6, 0x3f, 0x60, 0x0e, 0xf6
  };

  static const uint8_t kProof[] = {
      0xbf, 0xc6, 0xcf, 0x38, 0x59, 0x12, 0x7f, 0x5f, 0xe2, 0x55, 0x48, 0x85,
      0x98, 0x56, 0xd6, 0xb7, 0xfa, 0x1c, 0x74, 0x59, 0xf0, 0xba, 0x57, 0x12,
      0xa8, 0x06, 0xfc, 0x09, 0x1a, 0x30, 0x00, 0xc4, 0x2d, 0x8b, 0xa3, 0x4f,
      0xf4, 0x5f, 0x32, 0xa5, 0x2e, 0x40, 0x53, 0x3e, 0xfd, 0x2a, 0x03, 0xbc,
      0x87, 0xf3, 0xbf, 0x4f, 0x9f, 0x58, 0x02, 0x82, 0x97, 0xcc, 0xb9, 0xcc,
      0xb1, 0x8a, 0xe7, 0x18, 0x2b, 0xcd, 0x1e, 0xf2, 0x39, 0xdf, 0x77, 0xe3,
      0xbe, 0x65, 0xef, 0x14, 0x7f, 0x3a, 0xcf, 0x8b, 0xc9, 0xcb, 0xfc, 0x55,
      0x24, 0xb7, 0x02, 0x26, 0x34, 0x14, 0xf0, 0x43, 0xe3, 0xb7, 0xca, 0x2e
  };

  static const uint8_t kProofScalar[] = {
      0x80, 0x3d, 0x95, 0x5f, 0x0e, 0x07, 0x3a, 0x04, 0xaa, 0x5d, 0x92, 0xb3,
      0xfb, 0x73, 0x9f, 0x56, 0xf9, 0xdb, 0x00, 0x12, 0x66, 0x67, 0x7f, 0x62,
      0xc0, 0x95, 0x02, 0x1d, 0xb0, 0x18, 0xcd, 0x8c, 0xbb, 0x55, 0x94, 0x1d,
      0x40, 0x73, 0x69, 0x8c, 0xe4, 0x5c, 0x40, 0x5d, 0x13, 0x48, 0xb7, 0xb1
  };

  uint8_t blinded_buf[EC_MAX_UNCOMPRESSED];
  size_t blinded_len;
  ASSERT_TRUE(ec_point_uncompressed_from_compressed(
      group, blinded_buf, &blinded_len, kBlindedElement,
      sizeof(kBlindedElement)));

  CBS sign_input;
  CBS_init(&sign_input, blinded_buf, blinded_len);
  bssl::ScopedCBB response;
  ASSERT_TRUE(CBB_init(response.get(), 0));
  ASSERT_TRUE(voprf_pst1_sign_with_proof_scalar_for_testing(
      &key, response.get(), &sign_input, /*num_requested=*/1,
      /*num_to_issue=*/1,
      /*private_metadata=*/0, kProofScalar, sizeof(kProofScalar)));

  uint8_t evaluated_buf[EC_MAX_UNCOMPRESSED];
  size_t evaluated_len;
  ASSERT_TRUE(ec_point_uncompressed_from_compressed(
      group, evaluated_buf, &evaluated_len, kEvaluatedElement,
      sizeof(kEvaluatedElement)));

  bssl::ScopedCBB expected_response;
  ASSERT_TRUE(CBB_init(expected_response.get(), 0));
  ASSERT_TRUE(
      CBB_add_bytes(expected_response.get(), evaluated_buf, evaluated_len));
  ASSERT_TRUE(CBB_add_u16(expected_response.get(), sizeof(kProof)));
  ASSERT_TRUE(CBB_add_bytes(expected_response.get(), kProof, sizeof(kProof)));
  ASSERT_TRUE(CBB_flush(expected_response.get()));

  ASSERT_EQ(Bytes(CBB_data(expected_response.get()),
                  CBB_len(expected_response.get())),
            Bytes(CBB_data(response.get()), CBB_len(response.get())));
}

TEST(TrustTokenTest, PSTV1VOPRFTestVector2) {
  const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);
  TRUST_TOKEN_ISSUER_KEY key;
  ASSERT_TRUE(setup_voprf_test_key(group, &key));

  static const uint8_t kBlindedElement[] = {
      0x02, 0xf2, 0x74, 0x69, 0xe0, 0x59, 0x88, 0x6f, 0x22, 0x1b,
      0xe5, 0xf2, 0xcc, 0xa0, 0x3d, 0x2b, 0xdc, 0x61, 0xe5, 0x52,
      0x21, 0x72, 0x1c, 0x3b, 0x3e, 0x56, 0xfc, 0x01, 0x2e, 0x36,
      0xd3, 0x1a, 0xe5, 0xf8, 0xdc, 0x05, 0x81, 0x09, 0x59, 0x15,
      0x56, 0xa6, 0xdb, 0xd3, 0xa8, 0xc6, 0x9c, 0x43, 0x3b
  };

  static const uint8_t kEvaluatedElement[] = {
      0x03, 0xf1, 0x6f, 0x90, 0x39, 0x47, 0x03, 0x54, 0x00, 0xe9,
      0x6b, 0x7f, 0x53, 0x1a, 0x38, 0xd4, 0xa0, 0x7a, 0xc8, 0x9a,
      0x80, 0xf8, 0x9d, 0x86, 0xa1, 0xbf, 0x08, 0x9c, 0x52, 0x5a,
      0x92, 0xc7, 0xf4, 0x73, 0x37, 0x29, 0xca, 0x30, 0xc5, 0x6c,
      0xe7, 0x8b, 0x1a, 0xb4, 0xf7, 0xd9, 0x2d, 0xb8, 0xb4
  };

  static const uint8_t kProof[] = {
      0xd0, 0x05, 0xd6, 0xda, 0xaa, 0xd7, 0x57, 0x14, 0x14, 0xc1, 0xe0,
      0xc7, 0x5f, 0x7e, 0x57, 0xf2, 0x11, 0x3c, 0xa9, 0xf4, 0x60, 0x4e,
      0x84, 0xbc, 0x90, 0xf9, 0xbe, 0x52, 0xda, 0x89, 0x6f, 0xff, 0x3b,
      0xee, 0x49, 0x6d, 0xcd, 0xe2, 0xa5, 0x78, 0xae, 0x9d, 0xf3, 0x15,
      0x03, 0x25, 0x85, 0xf8, 0x01, 0xfb, 0x21, 0xc6, 0x08, 0x0a, 0xc0,
      0x56, 0x72, 0xb2, 0x91, 0xe5, 0x75, 0xa4, 0x02, 0x95, 0xb3, 0x06,
      0xd9, 0x67, 0x71, 0x7b, 0x28, 0xe0, 0x8f, 0xcc, 0x8a, 0xd1, 0xca,
      0xb4, 0x78, 0x45, 0xd1, 0x6a, 0xf7, 0x3b, 0x3e, 0x64, 0x3d, 0xdc,
      0xc1, 0x91, 0x20, 0x8e, 0x71, 0xc6, 0x46, 0x30
  };

  static const uint8_t kProofScalar[] = {
      0x80, 0x3d, 0x95, 0x5f, 0x0e, 0x07, 0x3a, 0x04, 0xaa, 0x5d, 0x92, 0xb3,
      0xfb, 0x73, 0x9f, 0x56, 0xf9, 0xdb, 0x00, 0x12, 0x66, 0x67, 0x7f, 0x62,
      0xc0, 0x95, 0x02, 0x1d, 0xb0, 0x18, 0xcd, 0x8c, 0xbb, 0x55, 0x94, 0x1d,
      0x40, 0x73, 0x69, 0x8c, 0xe4, 0x5c, 0x40, 0x5d, 0x13, 0x48, 0xb7, 0xb1
  };

  uint8_t blinded_buf[EC_MAX_UNCOMPRESSED];
  size_t blinded_len;
  ASSERT_TRUE(ec_point_uncompressed_from_compressed(
      group, blinded_buf, &blinded_len, kBlindedElement,
      sizeof(kBlindedElement)));

  CBS sign_input;
  CBS_init(&sign_input, blinded_buf, blinded_len);
  bssl::ScopedCBB response;
  ASSERT_TRUE(CBB_init(response.get(), 0));
  ASSERT_TRUE(voprf_pst1_sign_with_proof_scalar_for_testing(
      &key, response.get(), &sign_input, /*num_requested=*/1,
      /*num_to_issue=*/1,
      /*private_metadata=*/0, kProofScalar, sizeof(kProofScalar)));

  uint8_t evaluated_buf[EC_MAX_UNCOMPRESSED];
  size_t evaluated_len;
  ASSERT_TRUE(ec_point_uncompressed_from_compressed(
      group, evaluated_buf, &evaluated_len, kEvaluatedElement,
      sizeof(kEvaluatedElement)));

  bssl::ScopedCBB expected_response;
  ASSERT_TRUE(CBB_init(expected_response.get(), 0));
  ASSERT_TRUE(
      CBB_add_bytes(expected_response.get(), evaluated_buf, evaluated_len));
  ASSERT_TRUE(CBB_add_u16(expected_response.get(), sizeof(kProof)));
  ASSERT_TRUE(CBB_add_bytes(expected_response.get(), kProof, sizeof(kProof)));
  ASSERT_TRUE(CBB_flush(expected_response.get()));

  ASSERT_EQ(Bytes(CBB_data(expected_response.get()),
                  CBB_len(expected_response.get())),
            Bytes(CBB_data(response.get()), CBB_len(response.get())));
}

TEST(TrustTokenTest, PSTV1VOPRFTestVector3) {
  const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);
  TRUST_TOKEN_ISSUER_KEY key;
  ASSERT_TRUE(setup_voprf_test_key(group, &key));

  static const uint8_t kBlindedElement1[] = {
      0x02, 0xd3, 0x38, 0xc0, 0x5c, 0xbe, 0xcb, 0x82, 0xde, 0x13,
      0xd6, 0x70, 0x0f, 0x09, 0xcb, 0x61, 0x19, 0x05, 0x43, 0xa7,
      0xb7, 0xe2, 0xc6, 0xcd, 0x4f, 0xca, 0x56, 0x88, 0x7e, 0x56,
      0x4e, 0xa8, 0x26, 0x53, 0xb2, 0x7f, 0xda, 0xd3, 0x83, 0x99,
      0x5e, 0xa6, 0xd0, 0x2c, 0xf2, 0x6d, 0x0e, 0x24, 0xd9
  };
  static const uint8_t kBlindedElement2[] = {
      0x02, 0xfa, 0x02, 0x47, 0x0d, 0x7f, 0x15, 0x10, 0x18, 0xb4,
      0x1e, 0x82, 0x22, 0x3c, 0x32, 0xfa, 0xd8, 0x24, 0xde, 0x6a,
      0xd4, 0xb5, 0xce, 0x9f, 0x8e, 0x9f, 0x98, 0x08, 0x3c, 0x9a,
      0x72, 0x6d, 0xe9, 0xa1, 0xfc, 0x39, 0xd7, 0xa0, 0xcb, 0x6f,
      0x4f, 0x18, 0x8d, 0xd9, 0xce, 0xa0, 0x14, 0x74, 0xcd
  };

  static const uint8_t kEvaluatedElement1[] = {
      0x02, 0xa7, 0xbb, 0xa5, 0x89, 0xb3, 0xe8, 0x67, 0x2a, 0xa1,
      0x9e, 0x8f, 0xd2, 0x58, 0xde, 0x2e, 0x6a, 0xae, 0x20, 0x10,
      0x1c, 0x8d, 0x76, 0x12, 0x46, 0xde, 0x97, 0xa6, 0xb5, 0xee,
      0x9c, 0xf1, 0x05, 0xfe, 0xbc, 0xe4, 0x32, 0x7a, 0x32, 0x62,
      0x55, 0xa3, 0xc6, 0x04, 0xf6, 0x3f, 0x60, 0x0e, 0xf6
  };

  static const uint8_t kEvaluatedElement2[] = {
      0x02, 0x8e, 0x9e, 0x11, 0x56, 0x25, 0xff, 0x4c, 0x2f, 0x07,
      0xbf, 0x87, 0xce, 0x3f, 0xd7, 0x3f, 0xc7, 0x79, 0x94, 0xa7,
      0xa0, 0xc1, 0xdf, 0x03, 0xd2, 0xa6, 0x30, 0xa3, 0xd8, 0x45,
      0x93, 0x0e, 0x2e, 0x63, 0xa1, 0x65, 0xb1, 0x14, 0xd9, 0x8f,
      0xe3, 0x4e, 0x61, 0xb6, 0x8d, 0x23, 0xc0, 0xb5, 0x0a
  };

  static const uint8_t kProof[] = {
      0x6d, 0x8d, 0xcb, 0xd2, 0xfc, 0x95, 0x55, 0x0a, 0x02, 0x21, 0x1f,
      0xb7, 0x8a, 0xfd, 0x01, 0x39, 0x33, 0xf3, 0x07, 0xd2, 0x1e, 0x7d,
      0x85, 0x5b, 0x0b, 0x1e, 0xd0, 0xaf, 0x78, 0x07, 0x6d, 0x81, 0x37,
      0xad, 0x8b, 0x0a, 0x1b, 0xfa, 0x05, 0x67, 0x6d, 0x32, 0x52, 0x49,
      0xc1, 0xdb, 0xb9, 0xa5, 0x2b, 0xd8, 0x1b, 0x1c, 0x2b, 0x7b, 0x0e,
      0xfc, 0x77, 0xcf, 0x7b, 0x27, 0x8e, 0x1c, 0x94, 0x7f, 0x62, 0x83,
      0xf1, 0xd4, 0xc5, 0x13, 0x05, 0x3f, 0xc0, 0xad, 0x19, 0xe0, 0x26,
      0xfb, 0x0c, 0x30, 0x65, 0x4b, 0x53, 0xd9, 0xce, 0xa4, 0xb8, 0x7b,
      0x03, 0x72, 0x71, 0xb5, 0xd2, 0xe2, 0xd0, 0xea
  };

  static const uint8_t kProofScalar[] = {
      0xa0, 0x97, 0xe7, 0x22, 0xed, 0x24, 0x27, 0xde, 0x86, 0x96,
      0x69, 0x10, 0xac, 0xba, 0x9f, 0x5c, 0x35, 0x0e, 0x80, 0x40,
      0xf8, 0x28, 0xbf, 0x6c, 0xec, 0xa2, 0x74, 0x05, 0x42, 0x0c,
      0xdf, 0x3d, 0x63, 0xcb, 0x3a, 0xef, 0x00, 0x5f, 0x40, 0xba,
      0x51, 0x94, 0x3c, 0x80, 0x26, 0x87, 0x79, 0x63
  };

  uint8_t blinded_buf[2*EC_MAX_UNCOMPRESSED];
  size_t blinded_len;
  ASSERT_TRUE(ec_point_uncompressed_from_compressed(
      group, blinded_buf, &blinded_len, kBlindedElement1,
      sizeof(kBlindedElement1)));
  size_t offset = blinded_len;
  ASSERT_TRUE(ec_point_uncompressed_from_compressed(
      group, blinded_buf + offset, &blinded_len, kBlindedElement2,
      sizeof(kBlindedElement2)));

  CBS sign_input;
  CBS_init(&sign_input, blinded_buf, offset + blinded_len);
  bssl::ScopedCBB response;
  ASSERT_TRUE(CBB_init(response.get(), 0));
  ASSERT_TRUE(voprf_pst1_sign_with_proof_scalar_for_testing(
      &key, response.get(), &sign_input, /*num_requested=*/2,
      /*num_to_issue=*/2,
      /*private_metadata=*/0, kProofScalar, sizeof(kProofScalar)));

  uint8_t evaluated_buf[2 * EC_MAX_UNCOMPRESSED];
  size_t evaluated_len;
  ASSERT_TRUE(ec_point_uncompressed_from_compressed(
      group, evaluated_buf, &evaluated_len, kEvaluatedElement1,
      sizeof(kEvaluatedElement1)));
  offset = evaluated_len;
  ASSERT_TRUE(ec_point_uncompressed_from_compressed(
      group, evaluated_buf + offset, &evaluated_len, kEvaluatedElement2,
      sizeof(kEvaluatedElement2)));

  bssl::ScopedCBB expected_response;
  ASSERT_TRUE(CBB_init(expected_response.get(), 0));
  ASSERT_TRUE(CBB_add_bytes(expected_response.get(), evaluated_buf,
                            offset + evaluated_len));
  ASSERT_TRUE(CBB_add_u16(expected_response.get(), sizeof(kProof)));
  ASSERT_TRUE(CBB_add_bytes(expected_response.get(), kProof, sizeof(kProof)));
  ASSERT_TRUE(CBB_flush(expected_response.get()));

  ASSERT_EQ(Bytes(CBB_data(expected_response.get()),
                  CBB_len(expected_response.get())),
            Bytes(CBB_data(response.get()), CBB_len(response.get())));
}

// ATHM test vectors from draft-yun-cfrg-athm.

TEST(TrustTokenTest, ATHMHGeneratorTestVector) {
  // Verify H derivation formula matches draft-yun-cfrg-athm test vectors.
  //
  // Per the spec, Section 3.1:
  //   generatorH = HashToGroup(SerializeElement(generatorG), "generatorH")
  //   DST = "HashToGroup-" || contextString || "generatorH"
  //   contextString = "ATHMV1-P256-<nBuckets>-<deploymentId>"
  //
  // Test vector params:
  //   deployment_id = "test_vector_deployment_id"
  //   nBuckets = 4
  //   contextString = "ATHMV1-P256-4-test_vector_deployment_id"
  //   DST = "HashToGroup-ATHMV1-P256-4-test_vector_deployment_idgeneratorH"
  //   msg = compressed encoding of P-256 generator G

  // Expected H from spec test vectors (compressed).
  static const uint8_t kExpectedHCompressed[] = {
      0x02, 0x36, 0x1f, 0xc6, 0x83, 0x1d, 0x37, 0x96, 0xa8, 0x26, 0x12,
      0xdf, 0xfb, 0x23, 0x1e, 0xc6, 0x72, 0x53, 0xb2, 0xf6, 0x9d, 0xbb,
      0x12, 0x4c, 0x9a, 0x0f, 0x99, 0x17, 0xb4, 0xe3, 0x18, 0x0d, 0x03};

  // DST for the test vector deployment_id.
  static const uint8_t kDST[] =
      "HashToGroup-ATHMV1-P256-4-test_vector_deployment_idgeneratorH";

  // Compressed encoding of the P-256 generator G (NIST standard value).
  static const uint8_t kGeneratorGCompressed[] = {
      0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
      0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
      0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96};

  const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  ASSERT_TRUE(group);

  // Compute H using the spec's formula.
  EC_JACOBIAN h_j;
  ASSERT_TRUE(ec_hash_to_curve_p256_xmd_sha256_sswu(
      group, &h_j, kDST, sizeof(kDST) - 1, kGeneratorGCompressed,
      sizeof(kGeneratorGCompressed)));

  EC_AFFINE h_a;
  ASSERT_TRUE(ec_jacobian_to_affine(group, &h_a, &h_j));

  uint8_t h_uncompressed[65];
  ASSERT_EQ(65u, ec_point_to_bytes(group, &h_a, POINT_CONVERSION_UNCOMPRESSED,
                                   h_uncompressed, sizeof(h_uncompressed)));

  // Convert expected H from compressed to uncompressed for comparison.
  uint8_t expected_uncompressed[EC_MAX_UNCOMPRESSED];
  size_t expected_len;
  ASSERT_TRUE(ec_point_uncompressed_from_compressed(
      group, expected_uncompressed, &expected_len, kExpectedHCompressed,
      sizeof(kExpectedHCompressed)));

  EXPECT_EQ(Bytes(h_uncompressed, 65),
            Bytes(expected_uncompressed, expected_len));
}

TEST(TrustTokenTest, ATHMVerifyTokenTestVector) {
  // Private key scalars from draft-yun-cfrg-athm test vectors.
  // Spec serialization order: x, y, z, r_x, r_y.
  static const uint8_t kPrivKeyX[] = {
      0x02, 0x3f, 0x37, 0x20, 0x3a, 0x24, 0x76, 0xc4, 0x25, 0x66, 0xa6,
      0x1c, 0xc5, 0x5c, 0x3c, 0xa8, 0x75, 0xdb, 0xb4, 0xcc, 0x41, 0xc0,
      0xde, 0xb7, 0x89, 0xf8, 0xe7, 0xbf, 0x88, 0x18, 0x36, 0x38};
  static const uint8_t kPrivKeyY[] = {
      0x1e, 0xcc, 0x36, 0x86, 0xb6, 0x0e, 0xe3, 0xb8, 0x4b, 0x6c, 0x7d,
      0x32, 0x1d, 0x70, 0xd5, 0xc0, 0x6e, 0x9d, 0xac, 0x63, 0xa4, 0xd0,
      0xa7, 0x9d, 0x73, 0x1b, 0x17, 0xc0, 0xd0, 0x4d, 0x03, 0x0d};
  static const uint8_t kPrivKeyZ[] = {
      0x01, 0x27, 0x4d, 0xd1, 0xee, 0x52, 0x16, 0xc2, 0x04, 0xfb, 0x69,
      0x8d, 0xae, 0xa4, 0x5b, 0x52, 0xe9, 0x8b, 0x6f, 0x0f, 0xdd, 0x04,
      0x6d, 0xcc, 0x3a, 0x86, 0xbb, 0x07, 0x9e, 0x36, 0xf0, 0x24};
  static const uint8_t kPrivKeyRx[] = {
      0x14, 0x7e, 0x4b, 0x87, 0x5d, 0x59, 0xa9, 0xef, 0x43, 0x2b, 0x8e,
      0x45, 0xb0, 0x4a, 0x98, 0xc4, 0xb1, 0x9d, 0xc8, 0xc7, 0x47, 0x5f,
      0x5d, 0xce, 0x42, 0x59, 0xb4, 0xca, 0x2d, 0xd6, 0x72, 0x82};
  static const uint8_t kPrivKeyRy[] = {
      0xb4, 0x78, 0xb8, 0x70, 0x2c, 0x1d, 0x25, 0x69, 0xfe, 0x52, 0xe5,
      0xd7, 0xdb, 0xad, 0xec, 0x62, 0x23, 0xcd, 0x10, 0xfd, 0x4b, 0x50,
      0x4d, 0xab, 0xac, 0x7f, 0xff, 0x23, 0xa3, 0x73, 0x63, 0xd1};

  // Token from test vectors: t (32B) + P compressed (33B) + Q compressed (33B).
  // hidden_metadata = 3.
  static const uint8_t kTokenT[] = {
      0xb7, 0xd8, 0x31, 0x0e, 0x18, 0x99, 0xa7, 0x48, 0xb3, 0x00, 0x0e,
      0x52, 0x2d, 0x32, 0x0b, 0x29, 0x88, 0x0e, 0x07, 0x11, 0x9f, 0x1a,
      0x77, 0x6b, 0x63, 0x9b, 0x3c, 0xe0, 0xa4, 0xa0, 0x1a, 0x9f};
  static const uint8_t kTokenPCompressed[] = {
      0x02, 0x12, 0x3d, 0x0c, 0x12, 0x5d, 0xe3, 0xd1, 0x22, 0x57, 0x7b,
      0x33, 0x5a, 0x8f, 0x66, 0x16, 0xd7, 0x35, 0xe9, 0x40, 0x0b, 0x60,
      0xdc, 0xde, 0x57, 0xef, 0xf0, 0x56, 0xe9, 0xcb, 0xbd, 0x2b, 0x3c};
  static const uint8_t kTokenQCompressed[] = {
      0x03, 0xa0, 0x62, 0xc5, 0xb4, 0x15, 0x07, 0xe1, 0xfe, 0x08, 0x9d,
      0x0c, 0x3b, 0x41, 0x32, 0xd8, 0x4e, 0xce, 0x1d, 0x4a, 0x9d, 0xfc,
      0x0b, 0xf4, 0xf0, 0x58, 0x8d, 0x66, 0x0f, 0x25, 0xbd, 0xf6, 0xcf};

  // Expected public key points (compressed) from test vectors.
  static const uint8_t kExpectedZCompressed[] = {
      0x03, 0x2b, 0x80, 0x02, 0x4e, 0xe8, 0x18, 0xd7, 0x09, 0x19, 0x67,
      0x80, 0xa8, 0x4a, 0xff, 0xe0, 0x87, 0x89, 0xf5, 0x71, 0x52, 0x9f,
      0xcc, 0xc1, 0xac, 0xce, 0x07, 0xee, 0xa2, 0xdf, 0x2f, 0xc6, 0x5f};
  static const uint8_t kExpectedCxCompressed[] = {
      0x03, 0x5f, 0x6a, 0x6e, 0xb8, 0x4b, 0xea, 0x9c, 0x13, 0x61, 0x11,
      0x94, 0x62, 0xbd, 0xa8, 0x63, 0xc4, 0x7c, 0x3b, 0x43, 0xe5, 0x3e,
      0x9e, 0x5e, 0x7a, 0x87, 0x96, 0xba, 0x1b, 0x92, 0x4d, 0x09, 0x3e};
  static const uint8_t kExpectedCyCompressed[] = {
      0x03, 0xb7, 0xf1, 0x6d, 0xf0, 0xad, 0x82, 0xcb, 0xd8, 0xbd, 0x6a,
      0x04, 0xed, 0x42, 0x71, 0x07, 0xad, 0xf5, 0xa3, 0xd4, 0xba, 0x84,
      0x0e, 0x9b, 0x34, 0x1a, 0x3b, 0xad, 0xc1, 0xd9, 0xb7, 0xfe, 0x19};

  const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  ASSERT_TRUE(group);

  // Load the private key scalars directly into the issuer key struct.
  // athm_v1_read only needs x0=x, y0=y, xs=z for token verification.
  // We bypass athm_v1_issuer_key_from_bytes because it computes public keys
  // using the v1 method's H (empty deployment_id), but the test vectors use
  // deployment_id="test_vector_deployment_id".
  TRUST_TOKEN_ISSUER_KEY issuer_key;
  OPENSSL_memset(&issuer_key, 0, sizeof(issuer_key));
  ASSERT_TRUE(
      ec_scalar_from_bytes(group, &issuer_key.x0, kPrivKeyX, 32));   // x
  ASSERT_TRUE(
      ec_scalar_from_bytes(group, &issuer_key.y0, kPrivKeyY, 32));   // y
  ASSERT_TRUE(
      ec_scalar_from_bytes(group, &issuer_key.x1, kPrivKeyRx, 32));  // r_x
  ASSERT_TRUE(
      ec_scalar_from_bytes(group, &issuer_key.y1, kPrivKeyRy, 32));  // r_y
  ASSERT_TRUE(
      ec_scalar_from_bytes(group, &issuer_key.xs, kPrivKeyZ, 32));   // z

  // Verify Z = z*G matches spec.
  EC_JACOBIAN Z_j;
  ASSERT_TRUE(ec_point_mul_scalar_base(group, &Z_j, &issuer_key.xs));
  EC_AFFINE Z_a;
  ASSERT_TRUE(ec_jacobian_to_affine(group, &Z_a, &Z_j));
  uint8_t Z_computed[65];
  ASSERT_EQ(65u, ec_point_to_bytes(group, &Z_a, POINT_CONVERSION_UNCOMPRESSED,
                                   Z_computed, sizeof(Z_computed)));
  uint8_t Z_expected[EC_MAX_UNCOMPRESSED];
  size_t Z_len;
  ASSERT_TRUE(ec_point_uncompressed_from_compressed(
      group, Z_expected, &Z_len, kExpectedZCompressed,
      sizeof(kExpectedZCompressed)));
  EXPECT_EQ(Bytes(Z_computed, 65), Bytes(Z_expected, Z_len));

  // Verify C_x = x*G + r_x*H and C_y = y*G + r_y*H using the spec's H.
  // First compute H with the test vector's deployment_id.
  static const uint8_t kDST[] =
      "HashToGroup-ATHMV1-P256-4-test_vector_deployment_idgeneratorH";
  static const uint8_t kGeneratorGCompressed[] = {
      0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
      0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
      0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96};
  EC_JACOBIAN H_j;
  ASSERT_TRUE(ec_hash_to_curve_p256_xmd_sha256_sswu(
      group, &H_j, kDST, sizeof(kDST) - 1, kGeneratorGCompressed,
      sizeof(kGeneratorGCompressed)));

  // C_x = x*G + r_x*H
  EC_JACOBIAN xG, rxH, Cx_j;
  ASSERT_TRUE(ec_point_mul_scalar_base(group, &xG, &issuer_key.x0));
  ASSERT_TRUE(ec_point_mul_scalar(group, &rxH, &H_j, &issuer_key.x1));
  group->meth->add(group, &Cx_j, &xG, &rxH);
  EC_AFFINE Cx_a;
  ASSERT_TRUE(ec_jacobian_to_affine(group, &Cx_a, &Cx_j));
  uint8_t Cx_computed[65];
  ASSERT_EQ(65u, ec_point_to_bytes(group, &Cx_a, POINT_CONVERSION_UNCOMPRESSED,
                                   Cx_computed, sizeof(Cx_computed)));
  uint8_t Cx_expected[EC_MAX_UNCOMPRESSED];
  size_t Cx_len;
  ASSERT_TRUE(ec_point_uncompressed_from_compressed(
      group, Cx_expected, &Cx_len, kExpectedCxCompressed,
      sizeof(kExpectedCxCompressed)));
  EXPECT_EQ(Bytes(Cx_computed, 65), Bytes(Cx_expected, Cx_len));

  // C_y = y*G + r_y*H
  EC_JACOBIAN yG, ryH, Cy_j;
  ASSERT_TRUE(ec_point_mul_scalar_base(group, &yG, &issuer_key.y0));
  ASSERT_TRUE(ec_point_mul_scalar(group, &ryH, &H_j, &issuer_key.y1));
  group->meth->add(group, &Cy_j, &yG, &ryH);
  EC_AFFINE Cy_a;
  ASSERT_TRUE(ec_jacobian_to_affine(group, &Cy_a, &Cy_j));
  uint8_t Cy_computed[65];
  ASSERT_EQ(65u, ec_point_to_bytes(group, &Cy_a, POINT_CONVERSION_UNCOMPRESSED,
                                   Cy_computed, sizeof(Cy_computed)));
  uint8_t Cy_expected[EC_MAX_UNCOMPRESSED];
  size_t Cy_len;
  ASSERT_TRUE(ec_point_uncompressed_from_compressed(
      group, Cy_expected, &Cy_len, kExpectedCyCompressed,
      sizeof(kExpectedCyCompressed)));
  EXPECT_EQ(Bytes(Cy_computed, 65), Bytes(Cy_expected, Cy_len));

  // Construct the token in compressed format: t (32B) + P (33B) + Q (33B).
  uint8_t token[32 + 33 + 33];
  OPENSSL_memcpy(token, kTokenT, 32);
  OPENSSL_memcpy(token + 32, kTokenPCompressed, 33);
  OPENSSL_memcpy(token + 32 + 33, kTokenQCompressed, 33);

  // Verify the token. Expected hidden_metadata = 3.
  uint8_t nonce[TRUST_TOKEN_NONCE_SIZE];
  uint8_t private_metadata;
  ASSERT_TRUE(athm_v1_read(&issuer_key, nonce, &private_metadata, token,
                            sizeof(token), /*include_message=*/0, nullptr, 0));
  EXPECT_EQ(3u, private_metadata);
}

static std::vector<const TRUST_TOKEN_METHOD *> AllMethods() {
  return {
    TRUST_TOKEN_experiment_v1(),
    TRUST_TOKEN_experiment_v2_voprf(),
    TRUST_TOKEN_experiment_v2_pmb(),
    TRUST_TOKEN_pst_v1_voprf(),
    TRUST_TOKEN_pst_v1_pmb(),
    TRUST_TOKEN_athm_v1(),
    // TRUST_TOKEN_athm_v1_multikey() is not included here because the generic
    // SetupContexts() generates independent keys, violating the multi-key ATHM
    // constraint that all keys share the same z. Multi-key ATHM is tested by
    // dedicated ATHMMultiKey* tests.
  };
}

class TrustTokenProtocolTestBase : public ::testing::Test {
 public:
  explicit TrustTokenProtocolTestBase(const TRUST_TOKEN_METHOD *method_arg,
                                      bool use_msg)
      : method_(method_arg), use_msg_(use_msg) {}

  // KeyID returns the key ID associated with key index |i|.
  static uint32_t KeyID(size_t i) {
    assert(i <= UINT32_MAX);
    // Use a different value from the indices to that we do not mix them up.
    return static_cast<uint32_t>(7 + i);
  }

  const TRUST_TOKEN_METHOD *method() const { return method_; }

  bool use_message() const { return use_msg_; }

 protected:
  void SetupContexts() {
    client.reset(TRUST_TOKEN_CLIENT_new(method(), client_max_batchsize));
    ASSERT_TRUE(client);
    issuer.reset(TRUST_TOKEN_ISSUER_new(method(), issuer_max_batchsize));
    ASSERT_TRUE(issuer);

    // ATHM methods require deployment_id to be set before adding keys.
    if (method()->is_athm) {
      ASSERT_TRUE(
          TRUST_TOKEN_CLIENT_set_deployment_id(client.get(), nullptr, 0));
      ASSERT_TRUE(
          TRUST_TOKEN_ISSUER_set_deployment_id(issuer.get(), nullptr, 0));
    }

    for (size_t i = 0; i < method()->max_keys; i++) {
      uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
      uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
      size_t priv_key_len, pub_key_len, key_index;
      if (method()->is_athm) {
        ASSERT_TRUE(TRUST_TOKEN_generate_key_with_deployment_id(
            method(), priv_key, &priv_key_len,
            TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, pub_key, &pub_key_len,
            TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, KeyID(i), nullptr, 0));
      } else {
        ASSERT_TRUE(TRUST_TOKEN_generate_key(
            method(), priv_key, &priv_key_len,
            TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, pub_key, &pub_key_len,
            TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, KeyID(i)));
      }
      ASSERT_TRUE(TRUST_TOKEN_CLIENT_add_key(client.get(), &key_index, pub_key,
                                             pub_key_len));
      ASSERT_EQ(i, key_index);
      ASSERT_TRUE(
          TRUST_TOKEN_ISSUER_add_key(issuer.get(), priv_key, priv_key_len));
    }

    uint8_t public_key[32], private_key[64];
    ED25519_keypair(public_key, private_key);
    bssl::UniquePtr<EVP_PKEY> priv(
        EVP_PKEY_from_raw_private_key(EVP_pkey_ed25519(), private_key, 32));
    ASSERT_TRUE(priv);
    bssl::UniquePtr<EVP_PKEY> pub(
        EVP_PKEY_from_raw_public_key(EVP_pkey_ed25519(), public_key, 32));
    ASSERT_TRUE(pub);

    TRUST_TOKEN_CLIENT_set_srr_key(client.get(), pub.get());
    TRUST_TOKEN_ISSUER_set_srr_key(issuer.get(), priv.get());
    RAND_bytes(metadata_key, sizeof(metadata_key));
    ASSERT_TRUE(TRUST_TOKEN_ISSUER_set_metadata_key(issuer.get(), metadata_key,
                                                    sizeof(metadata_key)));
  }

  const TRUST_TOKEN_METHOD *method_;
  bool use_msg_;
  uint16_t client_max_batchsize = 10;
  uint16_t issuer_max_batchsize = 10;
  bssl::UniquePtr<TRUST_TOKEN_CLIENT> client;
  bssl::UniquePtr<TRUST_TOKEN_ISSUER> issuer;
  uint8_t metadata_key[32];
};

class TrustTokenProtocolTest
    : public TrustTokenProtocolTestBase,
      public testing::WithParamInterface<
          std::tuple<const TRUST_TOKEN_METHOD *, bool>> {
 public:
  TrustTokenProtocolTest()
      : TrustTokenProtocolTestBase(std::get<0>(GetParam()),
                                   std::get<1>(GetParam())) {}
};

INSTANTIATE_TEST_SUITE_P(TrustTokenAllProtocolTest, TrustTokenProtocolTest,
                         testing::Combine(testing::ValuesIn(AllMethods()),
                                          testing::Bool()));

TEST_P(TrustTokenProtocolTest, InvalidToken) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = nullptr, *issue_resp = nullptr;
  size_t msg_len, resp_len;

  size_t key_index;
  size_t tokens_issued;
  if (use_message()) {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance_over_message(
        client.get(), &issue_msg, &msg_len, 1, kMessage, sizeof(kMessage)));
  } else {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                  &msg_len, 1));
  }
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/KeyID(0), /*private_metadata=*/0,
      /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_TRUE(tokens);

  for (TRUST_TOKEN *token : tokens.get()) {
    // Corrupt the token.
    token->data[0] ^= 0x42;

    uint8_t *redeem_msg = nullptr, *redeem_resp = nullptr;
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_redemption(
        client.get(), &redeem_msg, &msg_len, token, nullptr, 0, 0));
    bssl::UniquePtr<uint8_t> free_redeem_msg(redeem_msg);
    uint32_t public_value;
    uint8_t private_value;
    TRUST_TOKEN *rtoken;
    uint8_t *client_data;
    size_t client_data_len;
    if (use_message()) {
      ASSERT_FALSE(TRUST_TOKEN_ISSUER_redeem_over_message(
          issuer.get(), &public_value, &private_value, &rtoken, &client_data,
          &client_data_len, redeem_msg, msg_len, kMessage, sizeof(kMessage)));
    } else {
      ASSERT_FALSE(TRUST_TOKEN_ISSUER_redeem(
          issuer.get(), &public_value, &private_value, &rtoken, &client_data,
          &client_data_len, redeem_msg, msg_len));
    }
    bssl::UniquePtr<uint8_t> free_redeem_resp(redeem_resp);
  }
}

TEST_P(TrustTokenProtocolTest, TruncatedIssuanceRequest) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = nullptr, *issue_resp = nullptr;
  size_t msg_len, resp_len;
  if (use_message()) {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance_over_message(
        client.get(), &issue_msg, &msg_len, 10, kMessage, sizeof(kMessage)));
  } else {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                  &msg_len, 10));
  }
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  msg_len = 10;
  size_t tokens_issued;
  ASSERT_FALSE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/KeyID(0), /*private_metadata=*/0,
      /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
}

TEST_P(TrustTokenProtocolTest, TruncatedIssuanceResponse) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = nullptr, *issue_resp = nullptr;
  size_t msg_len, resp_len;
  if (use_message()) {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance_over_message(
        client.get(), &issue_msg, &msg_len, 10, kMessage, sizeof(kMessage)));
  } else {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                  &msg_len, 10));
  }
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/KeyID(0), /*private_metadata=*/0,
      /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  resp_len = 10;
  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_FALSE(tokens);
}

TEST_P(TrustTokenProtocolTest, ExtraDataIssuanceResponse) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *request = nullptr, *response = nullptr;
  size_t request_len, response_len;
  if (use_message()) {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance_over_message(
        client.get(), &request, &request_len, 10, kMessage, sizeof(kMessage)));
  } else {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &request,
                                                  &request_len, 10));
  }
  bssl::UniquePtr<uint8_t> free_request(request);
  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(issuer.get(), &response, &response_len,
                                       &tokens_issued, request, request_len,
                                       /*public_metadata=*/KeyID(0),
                                       /*private_metadata=*/0,
                                       /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_response(response);
  std::vector<uint8_t> response2(response, response + response_len);
  response2.push_back(0);
  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index,
                                         response2.data(), response2.size()));
  ASSERT_FALSE(tokens);
}

TEST_P(TrustTokenProtocolTest, TruncatedRedemptionRequest) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = nullptr, *issue_resp = nullptr;
  size_t msg_len, resp_len;
  if (use_message()) {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance_over_message(
        client.get(), &issue_msg, &msg_len, 10, kMessage, sizeof(kMessage)));
  } else {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                  &msg_len, 10));
  }
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/KeyID(0), /*private_metadata=*/0,
      /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_TRUE(tokens);

  for (TRUST_TOKEN *token : tokens.get()) {
    const uint8_t kClientData[] = "\x70TEST CLIENT DATA";
    uint64_t kRedemptionTime = (method()->has_srr ? 13374242 : 0);

    uint8_t *redeem_msg = nullptr;
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_redemption(
        client.get(), &redeem_msg, &msg_len, token, kClientData,
        sizeof(kClientData) - 1, kRedemptionTime));
    bssl::UniquePtr<uint8_t> free_redeem_msg(redeem_msg);
    msg_len = 10;

    uint32_t public_value;
    uint8_t private_value;
    TRUST_TOKEN *rtoken;
    uint8_t *client_data;
    size_t client_data_len;
    if (use_message()) {
      ASSERT_FALSE(TRUST_TOKEN_ISSUER_redeem_over_message(
          issuer.get(), &public_value, &private_value, &rtoken, &client_data,
          &client_data_len, redeem_msg, msg_len, kMessage, sizeof(kMessage)));
    } else {
      ASSERT_FALSE(TRUST_TOKEN_ISSUER_redeem(
          issuer.get(), &public_value, &private_value, &rtoken, &client_data,
          &client_data_len, redeem_msg, msg_len));
    }
  }
}

TEST_P(TrustTokenProtocolTest, IssuedWithBadKeyID) {
  client.reset(TRUST_TOKEN_CLIENT_new(method(), client_max_batchsize));
  ASSERT_TRUE(client);
  issuer.reset(TRUST_TOKEN_ISSUER_new(method(), issuer_max_batchsize));
  ASSERT_TRUE(issuer);

  if (method()->is_athm) {
    ASSERT_TRUE(
        TRUST_TOKEN_CLIENT_set_deployment_id(client.get(), nullptr, 0));
    ASSERT_TRUE(
        TRUST_TOKEN_ISSUER_set_deployment_id(issuer.get(), nullptr, 0));
  }

  // We configure the client and the issuer with different key IDs and test
  // that the client notices.
  const uint32_t kClientKeyID = 0;
  const uint32_t kIssuerKeyID = 42;

  uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_len, pub_key_len, key_index;
  if (method()->is_athm) {
    ASSERT_TRUE(TRUST_TOKEN_generate_key_with_deployment_id(
        method(), priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
        pub_key, &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, kClientKeyID,
        nullptr, 0));
  } else {
    ASSERT_TRUE(TRUST_TOKEN_generate_key(
        method(), priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
        pub_key, &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, kClientKeyID));
  }
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_add_key(client.get(), &key_index, pub_key,
                                         pub_key_len));
  ASSERT_EQ(0UL, key_index);

  if (method()->is_athm) {
    ASSERT_TRUE(TRUST_TOKEN_generate_key_with_deployment_id(
        method(), priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
        pub_key, &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, kIssuerKeyID,
        nullptr, 0));
  } else {
    ASSERT_TRUE(TRUST_TOKEN_generate_key(
        method(), priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
        pub_key, &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, kIssuerKeyID));
  }
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_add_key(issuer.get(), priv_key, priv_key_len));


  uint8_t public_key[32], private_key[64];
  ED25519_keypair(public_key, private_key);
  bssl::UniquePtr<EVP_PKEY> priv(
      EVP_PKEY_from_raw_private_key(EVP_pkey_ed25519(), private_key, 32));
  ASSERT_TRUE(priv);
  bssl::UniquePtr<EVP_PKEY> pub(
      EVP_PKEY_from_raw_public_key(EVP_pkey_ed25519(), public_key, 32));
  ASSERT_TRUE(pub);

  TRUST_TOKEN_CLIENT_set_srr_key(client.get(), pub.get());
  TRUST_TOKEN_ISSUER_set_srr_key(issuer.get(), priv.get());
  RAND_bytes(metadata_key, sizeof(metadata_key));
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_set_metadata_key(issuer.get(), metadata_key,
                                                  sizeof(metadata_key)));


  uint8_t *issue_msg = nullptr, *issue_resp = nullptr;
  size_t msg_len, resp_len;
  if (use_message()) {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance_over_message(
        client.get(), &issue_msg, &msg_len, 10, kMessage, sizeof(kMessage)));
  } else {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                  &msg_len, 10));
  }
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/42, /*private_metadata=*/0, /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_FALSE(tokens);
}

class TrustTokenMetadataTest
    : public TrustTokenProtocolTestBase,
      public testing::WithParamInterface<
    std::tuple<const TRUST_TOKEN_METHOD *, bool, int, bool>> {
 public:
  TrustTokenMetadataTest()
      : TrustTokenProtocolTestBase(std::get<0>(GetParam()),
                                   std::get<1>(GetParam())) {}

  int public_metadata() { return std::get<2>(GetParam()); }
  bool private_metadata() { return std::get<3>(GetParam()); }
};

TEST_P(TrustTokenMetadataTest, SetAndGetMetadata) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = nullptr, *issue_resp = nullptr;
  size_t msg_len, resp_len;
  if (use_message()) {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance_over_message(
        client.get(), &issue_msg, &msg_len, 10, kMessage, sizeof(kMessage)));
  } else {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                  &msg_len, 10));
  }
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);

  // Make a copy to test that the testing API works.
  bssl::UniquePtr<TRUST_TOKEN_CLIENT> client_copy(
      TRUST_TOKEN_CLIENT_dup_for_testing(client.get()));
  ASSERT_TRUE(client_copy);

  size_t tokens_issued;
  bool result = TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      public_metadata(), private_metadata(), /*max_issuance=*/1);
  if ((!method()->has_private_metadata && private_metadata()) ||
      static_cast<uint32_t>(public_metadata()) >= KeyID(method()->max_keys)) {
    ASSERT_FALSE(result);
    return;
  }
  ASSERT_TRUE(result);
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);

  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_TRUE(tokens);
  EXPECT_EQ(1u, sk_TRUST_TOKEN_num(tokens.get()));

  // Test that the testing copy gave the same result.
  size_t key_index2;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens2(
      TRUST_TOKEN_CLIENT_finish_issuance(client_copy.get(), &key_index2,
                                         issue_resp, resp_len));
  ASSERT_TRUE(tokens2);
  EXPECT_EQ(key_index, key_index2);
  EXPECT_EQ(1u, sk_TRUST_TOKEN_num(tokens2.get()));
  // ATHM's unblind step uses random re-randomization (c), so duplicated
  // clients will produce different token bytes. Skip byte comparison for ATHM.
  if (method() != TRUST_TOKEN_athm_v1()) {
    EXPECT_EQ(Bytes(sk_TRUST_TOKEN_value(tokens.get(), 0)->data,
                    sk_TRUST_TOKEN_value(tokens.get(), 0)->len),
              Bytes(sk_TRUST_TOKEN_value(tokens2.get(), 0)->data,
                    sk_TRUST_TOKEN_value(tokens2.get(), 0)->len));
  }

  for (TRUST_TOKEN *token : tokens.get()) {
    const uint8_t kClientData[] = "\x70TEST CLIENT DATA";
    uint64_t kRedemptionTime = (method()->has_srr ? 13374242 : 0);

    uint8_t *redeem_msg = nullptr;
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_redemption(
        client.get(), &redeem_msg, &msg_len, token, kClientData,
        sizeof(kClientData) - 1, kRedemptionTime));
    bssl::UniquePtr<uint8_t> free_redeem_msg(redeem_msg);
    uint32_t public_value;
    uint8_t private_value;
    TRUST_TOKEN *rtoken;
    uint8_t *client_data;
    size_t client_data_len;
    if (use_message()) {
      ASSERT_TRUE(TRUST_TOKEN_ISSUER_redeem_over_message(
          issuer.get(), &public_value, &private_value, &rtoken, &client_data,
          &client_data_len, redeem_msg, msg_len, kMessage, sizeof(kMessage)));
    } else {
      ASSERT_TRUE(TRUST_TOKEN_ISSUER_redeem(
          issuer.get(), &public_value, &private_value, &rtoken, &client_data,
          &client_data_len, redeem_msg, msg_len));
    }
    bssl::UniquePtr<uint8_t> free_client_data(client_data);
    bssl::UniquePtr<TRUST_TOKEN> free_rtoken(rtoken);

    ASSERT_EQ(Bytes(kClientData, sizeof(kClientData) - 1),
              Bytes(client_data, client_data_len));
    ASSERT_EQ(public_value, static_cast<uint32_t>(public_metadata()));
    ASSERT_EQ(private_value, private_metadata());
  }
}

TEST_P(TrustTokenMetadataTest, TooManyRequests) {
  if ((!method()->has_private_metadata && private_metadata()) ||
      static_cast<uint32_t>(public_metadata()) >= KeyID(method()->max_keys)) {
    return;
  }

  issuer_max_batchsize = 1;
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = nullptr, *issue_resp = nullptr;
  size_t msg_len, resp_len;
  if (use_message()) {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance_over_message(
        client.get(), &issue_msg, &msg_len, 10, kMessage, sizeof(kMessage)));
  } else {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                  &msg_len, 10));
  }
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      public_metadata(), private_metadata(), /*max_issuance=*/1));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  ASSERT_EQ(tokens_issued, issuer_max_batchsize);
  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_TRUE(tokens);
  ASSERT_EQ(sk_TRUST_TOKEN_num(tokens.get()), 1UL);
}


TEST_P(TrustTokenMetadataTest, TruncatedProof) {
  if ((!method()->has_private_metadata && private_metadata()) ||
      static_cast<uint32_t>(public_metadata()) >= KeyID(method()->max_keys)) {
    return;
  }

  // ATHM uses per-token inline proofs rather than a batched DLEQ proof, so
  // this test's response manipulation does not apply.
  if (method() == TRUST_TOKEN_athm_v1()) {
    return;
  }

  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = nullptr, *issue_resp = nullptr;
  size_t msg_len, resp_len;
  if (use_message()) {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance_over_message(
        client.get(), &issue_msg, &msg_len, 10, kMessage, sizeof(kMessage)));
  } else {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                  &msg_len, 10));
  }
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      public_metadata(), private_metadata(), /*max_issuance=*/1));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);

  CBS real_response;
  CBS_init(&real_response, issue_resp, resp_len);
  uint16_t count;
  uint32_t parsed_public_metadata;
  bssl::ScopedCBB bad_response;
  ASSERT_TRUE(CBB_init(bad_response.get(), 0));
  ASSERT_TRUE(CBS_get_u16(&real_response, &count));
  ASSERT_TRUE(CBB_add_u16(bad_response.get(), count));
  ASSERT_TRUE(CBS_get_u32(&real_response, &parsed_public_metadata));
  ASSERT_TRUE(CBB_add_u32(bad_response.get(), parsed_public_metadata));

  const size_t kP384PointLen = 1 + 2 * (384 / 8);
  size_t token_length = TRUST_TOKEN_NONCE_SIZE + 2 * kP384PointLen;
  if (method() == TRUST_TOKEN_experiment_v1()) {
    token_length += 4;
  }
  if (method() == TRUST_TOKEN_experiment_v2_voprf() ||
      method() == TRUST_TOKEN_pst_v1_voprf()) {
    token_length = kP384PointLen;
  }
  for (size_t i = 0; i < count; i++) {
    ASSERT_TRUE(CBB_add_bytes(bad_response.get(), CBS_data(&real_response),
                              token_length));
    ASSERT_TRUE(CBS_skip(&real_response, token_length));
  }

  CBS tmp;
  ASSERT_TRUE(CBS_get_u16_length_prefixed(&real_response, &tmp));
  CBB dleq;
  ASSERT_TRUE(CBB_add_u16_length_prefixed(bad_response.get(), &dleq));
  ASSERT_TRUE(CBB_add_bytes(&dleq, CBS_data(&tmp), CBS_len(&tmp) - 2));
  ASSERT_TRUE(CBB_flush(bad_response.get()));

  uint8_t *bad_buf;
  size_t bad_len;
  ASSERT_TRUE(CBB_finish(bad_response.get(), &bad_buf, &bad_len));
  bssl::UniquePtr<uint8_t> free_bad(bad_buf);

  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, bad_buf,
                                         bad_len));
  ASSERT_FALSE(tokens);
}

TEST_P(TrustTokenMetadataTest, ExcessDataProof) {
  if (!method()->has_private_metadata && private_metadata()) {
    return;
  }

  // ATHM uses per-token inline proofs rather than a batched DLEQ proof, so
  // this test's response manipulation does not apply.
  if (method() == TRUST_TOKEN_athm_v1()) {
    return;
  }

  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = nullptr, *issue_resp = nullptr;
  size_t msg_len, resp_len;
  if (use_message()) {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance_over_message(
        client.get(), &issue_msg, &msg_len, 10, kMessage, sizeof(kMessage)));
  } else {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                  &msg_len, 10));
  }
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      public_metadata(), private_metadata(), /*max_issuance=*/1));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);

  CBS real_response;
  CBS_init(&real_response, issue_resp, resp_len);
  uint16_t count;
  uint32_t parsed_public_metadata;
  bssl::ScopedCBB bad_response;
  ASSERT_TRUE(CBB_init(bad_response.get(), 0));
  ASSERT_TRUE(CBS_get_u16(&real_response, &count));
  ASSERT_TRUE(CBB_add_u16(bad_response.get(), count));
  ASSERT_TRUE(CBS_get_u32(&real_response, &parsed_public_metadata));
  ASSERT_TRUE(CBB_add_u32(bad_response.get(), parsed_public_metadata));

  const size_t kP384PointLen = 1 + 2 * (384 / 8);
  size_t token_length = TRUST_TOKEN_NONCE_SIZE + 2 * kP384PointLen;
  if (method() == TRUST_TOKEN_experiment_v1()) {
    token_length += 4;
  }
  if (method() == TRUST_TOKEN_experiment_v2_voprf() ||
      method() == TRUST_TOKEN_pst_v1_voprf()) {
    token_length = kP384PointLen;
  }
  for (size_t i = 0; i < count; i++) {
    ASSERT_TRUE(CBB_add_bytes(bad_response.get(), CBS_data(&real_response),
                              token_length));
    ASSERT_TRUE(CBS_skip(&real_response, token_length));
  }

  CBS tmp;
  ASSERT_TRUE(CBS_get_u16_length_prefixed(&real_response, &tmp));
  CBB dleq;
  ASSERT_TRUE(CBB_add_u16_length_prefixed(bad_response.get(), &dleq));
  ASSERT_TRUE(CBB_add_bytes(&dleq, CBS_data(&tmp), CBS_len(&tmp)));
  ASSERT_TRUE(CBB_add_u16(&dleq, 42));
  ASSERT_TRUE(CBB_flush(bad_response.get()));

  uint8_t *bad_buf;
  size_t bad_len;
  ASSERT_TRUE(CBB_finish(bad_response.get(), &bad_buf, &bad_len));
  bssl::UniquePtr<uint8_t> free_bad(bad_buf);

  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, bad_buf,
                                         bad_len));
  ASSERT_FALSE(tokens);
}

INSTANTIATE_TEST_SUITE_P(
    TrustTokenAllMetadataTest, TrustTokenMetadataTest,
    testing::Combine(testing::ValuesIn(AllMethods()),
                     testing::Bool(),
                     testing::Values(TrustTokenProtocolTest::KeyID(0),
                                     TrustTokenProtocolTest::KeyID(1),
                                     TrustTokenProtocolTest::KeyID(2)),
                     testing::Bool()));

class TrustTokenBadKeyTest
    : public TrustTokenProtocolTestBase,
      public testing::WithParamInterface<
          std::tuple<const TRUST_TOKEN_METHOD *, bool, bool, int>> {
 public:
  TrustTokenBadKeyTest()
      : TrustTokenProtocolTestBase(std::get<0>(GetParam()),
                                   std::get<1>(GetParam())) {}

  bool private_metadata() { return std::get<2>(GetParam()); }
  int corrupted_key() { return std::get<3>(GetParam()); }
};

TEST_P(TrustTokenBadKeyTest, BadKey) {
  // For versions without private metadata, only corruptions of 'xs' (the 4th
  // entry in |scalars| below) result in a bad key, as the other scalars are
  // unused internally.
  if (!method()->has_private_metadata &&
      (private_metadata() || corrupted_key() != 4)) {
    return;
  }

  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = nullptr, *issue_resp = nullptr;
  size_t msg_len, resp_len;
  if (use_message()) {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance_over_message(
        client.get(), &issue_msg, &msg_len, 10, kMessage, sizeof(kMessage)));
  } else {
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                  &msg_len, 10));
  }
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);

  struct trust_token_issuer_key_st *key = &issuer->keys[0];
  EC_SCALAR *scalars[] = {&key->key.x0, &key->key.y0, &key->key.x1,
                          &key->key.y1, &key->key.xs, &key->key.ys};

  // Corrupt private key scalar.
  scalars[corrupted_key()]->words[0] ^= 42;

  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/7, private_metadata(), /*max_issuance=*/1));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));

  // ATHM's issuance proof (C_rho equation) detects corruption of any scalar
  // used in the bucket formula. With metadata bucket 0, y and r_y are scaled
  // by 0 and don't contribute, so their corruption is not detected.
  // ATHM also does not use |ys| (scalar index 5).
  if (method() == TRUST_TOKEN_athm_v1()) {
    int ck = corrupted_key();
    bool expect_success;
    if (ck == 5) {
      // ys is unused in ATHM.
      expect_success = true;
    } else if ((ck == 1 || ck == 3) && !private_metadata()) {
      // y (key 1) and r_y (key 3) are scaled by metadata. With bucket 0,
      // they don't contribute to V or rho.
      expect_success = true;
    } else {
      // All other corruptions are detected by the issuance proof.
      expect_success = false;
    }
    if (expect_success) {
      ASSERT_TRUE(tokens);
    } else {
      ASSERT_FALSE(tokens);
    }
    return;
  }

  // If the unused private key is corrupted, then the DLEQ proof should succeed.
  if ((corrupted_key() / 2 == 0 && private_metadata() == true) ||
      (corrupted_key() / 2 == 1 && private_metadata() == false)) {
    ASSERT_TRUE(tokens);
  } else {
    ASSERT_FALSE(tokens);
  }
}

INSTANTIATE_TEST_SUITE_P(TrustTokenAllBadKeyTest, TrustTokenBadKeyTest,
                         testing::Combine(testing::ValuesIn(AllMethods()),
                                          testing::Bool(),
                                          testing::Bool(),
                                          testing::Values(0, 1, 2, 3, 4, 5)));

// ATHM deployment_id and multi-key tests.

TEST(TrustTokenTest, ATHMDeploymentIdIssuance) {
  // Full end-to-end issuance/redemption with a custom deployment_id.
  const uint8_t kDeploymentId[] = "my-deployment";
  const TRUST_TOKEN_METHOD *method = TRUST_TOKEN_athm_v1();

  // Generate key with deployment_id.
  uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_len, pub_key_len;
  ASSERT_TRUE(TRUST_TOKEN_generate_key_with_deployment_id(
      method, priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
      pub_key, &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0,
      kDeploymentId, sizeof(kDeploymentId) - 1));

  // Set up client with deployment_id.
  bssl::UniquePtr<TRUST_TOKEN_CLIENT> client(
      TRUST_TOKEN_CLIENT_new(method, 10));
  ASSERT_TRUE(client);
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_set_deployment_id(
      client.get(), kDeploymentId, sizeof(kDeploymentId) - 1));
  size_t key_index;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_add_key(client.get(), &key_index, pub_key,
                                         pub_key_len));

  // Set up issuer with deployment_id.
  bssl::UniquePtr<TRUST_TOKEN_ISSUER> issuer(
      TRUST_TOKEN_ISSUER_new(method, 10));
  ASSERT_TRUE(issuer);
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_set_deployment_id(
      issuer.get(), kDeploymentId, sizeof(kDeploymentId) - 1));
  ASSERT_TRUE(
      TRUST_TOKEN_ISSUER_add_key(issuer.get(), priv_key, priv_key_len));

  uint8_t metadata_key[32];
  RAND_bytes(metadata_key, sizeof(metadata_key));
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_set_metadata_key(issuer.get(), metadata_key,
                                                   sizeof(metadata_key)));

  // Issuance.
  uint8_t *issue_msg = nullptr, *issue_resp = nullptr;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 1));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/0, /*private_metadata=*/1, /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_issue_resp(issue_resp);
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_TRUE(tokens);
  ASSERT_EQ(1u, sk_TRUST_TOKEN_num(tokens.get()));

  // Redemption.
  TRUST_TOKEN *token = sk_TRUST_TOKEN_value(tokens.get(), 0);
  uint8_t *redeem_msg = nullptr;
  size_t redeem_msg_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_redemption(
      client.get(), &redeem_msg, &redeem_msg_len, token, nullptr, 0, 0));
  bssl::UniquePtr<uint8_t> free_redeem_msg(redeem_msg);
  uint32_t public_value;
  uint8_t private_value;
  TRUST_TOKEN *rtoken;
  uint8_t *client_data;
  size_t client_data_len;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_redeem(issuer.get(), &public_value,
                                         &private_value, &rtoken, &client_data,
                                         &client_data_len, redeem_msg,
                                         redeem_msg_len));
  bssl::UniquePtr<TRUST_TOKEN> free_rtoken(rtoken);
  bssl::UniquePtr<uint8_t> free_client_data(client_data);
  EXPECT_EQ(0u, public_value);
  // For ATHM, private_value is the raw hidden metadata bucket index.
  EXPECT_EQ(1u, private_value);
}

TEST(TrustTokenTest, ATHMDeriveKeyFromSecret) {
  // End-to-end issuance/redemption using derive_key_from_secret with ATHM.
  const uint8_t kDeploymentId[] = "derive-test-deployment";
  const uint8_t kSecret[] = "test-secret-for-athm-key-derivation";
  const TRUST_TOKEN_METHOD *method = TRUST_TOKEN_athm_v1();

  // Derive key with deployment_id.
  uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_len, pub_key_len;
  ASSERT_TRUE(TRUST_TOKEN_derive_key_from_secret_with_deployment_id(
      method, priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
      pub_key, &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0, kSecret,
      sizeof(kSecret) - 1, kDeploymentId, sizeof(kDeploymentId) - 1));

  // Derive the same key again and verify private key determinism.
  // The public key includes a randomized Schnorr proof, so only the private
  // key is deterministic across calls.
  uint8_t priv_key2[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key2[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key2_len, pub_key2_len;
  ASSERT_TRUE(TRUST_TOKEN_derive_key_from_secret_with_deployment_id(
      method, priv_key2, &priv_key2_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
      pub_key2, &pub_key2_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0, kSecret,
      sizeof(kSecret) - 1, kDeploymentId, sizeof(kDeploymentId) - 1));
  EXPECT_EQ(Bytes(priv_key, priv_key_len), Bytes(priv_key2, priv_key2_len));

  // Set up client.
  bssl::UniquePtr<TRUST_TOKEN_CLIENT> client(
      TRUST_TOKEN_CLIENT_new(method, 10));
  ASSERT_TRUE(client);
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_set_deployment_id(
      client.get(), kDeploymentId, sizeof(kDeploymentId) - 1));
  size_t key_index;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_add_key(client.get(), &key_index, pub_key,
                                         pub_key_len));

  // Set up issuer.
  bssl::UniquePtr<TRUST_TOKEN_ISSUER> issuer(
      TRUST_TOKEN_ISSUER_new(method, 10));
  ASSERT_TRUE(issuer);
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_set_deployment_id(
      issuer.get(), kDeploymentId, sizeof(kDeploymentId) - 1));
  ASSERT_TRUE(
      TRUST_TOKEN_ISSUER_add_key(issuer.get(), priv_key, priv_key_len));

  uint8_t metadata_key[32];
  RAND_bytes(metadata_key, sizeof(metadata_key));
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_set_metadata_key(issuer.get(), metadata_key,
                                                   sizeof(metadata_key)));

  // Test all 4 metadata buckets with the derived key.
  for (uint8_t bucket = 0; bucket < 4; bucket++) {
    uint8_t *issue_msg = nullptr, *issue_resp = nullptr;
    size_t msg_len, resp_len;
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                  &msg_len, 1));
    bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
    size_t tokens_issued;
    ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
        issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg,
        msg_len, /*public_metadata=*/0, /*private_metadata=*/bucket,
        /*max_issuance=*/10));
    bssl::UniquePtr<uint8_t> free_issue_resp(issue_resp);
    bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
        TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                           resp_len));
    ASSERT_TRUE(tokens);
    ASSERT_EQ(1u, sk_TRUST_TOKEN_num(tokens.get()));

    // Redeem and verify the metadata bucket.
    TRUST_TOKEN *token = sk_TRUST_TOKEN_value(tokens.get(), 0);
    uint8_t *redeem_msg = nullptr;
    size_t redeem_msg_len;
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_redemption(
        client.get(), &redeem_msg, &redeem_msg_len, token, nullptr, 0, 0));
    bssl::UniquePtr<uint8_t> free_redeem_msg(redeem_msg);
    uint32_t public_value;
    uint8_t private_value;
    TRUST_TOKEN *rtoken;
    uint8_t *client_data;
    size_t client_data_len;
    ASSERT_TRUE(TRUST_TOKEN_ISSUER_redeem(issuer.get(), &public_value,
                                           &private_value, &rtoken,
                                           &client_data, &client_data_len,
                                           redeem_msg, redeem_msg_len));
    bssl::UniquePtr<TRUST_TOKEN> free_rtoken(rtoken);
    bssl::UniquePtr<uint8_t> free_client_data(client_data);
    EXPECT_EQ(bucket, private_value);
  }
}

TEST(TrustTokenTest, ATHMDeriveKeyRejectsWithoutDeploymentId) {
  // TRUST_TOKEN_derive_key_from_secret must fail for ATHM methods.
  const TRUST_TOKEN_METHOD *method = TRUST_TOKEN_athm_v1();
  uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_len, pub_key_len;
  ASSERT_FALSE(TRUST_TOKEN_derive_key_from_secret(
      method, priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
      pub_key, &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0,
      (const uint8_t *)"secret", 6));
}

TEST(TrustTokenTest, ATHMDeploymentIdMismatch) {
  // Client and issuer with different deployment_ids; unblind should fail.
  const uint8_t kDeploymentIdA[] = "deployment-A";
  const uint8_t kDeploymentIdB[] = "deployment-B";
  const TRUST_TOKEN_METHOD *method = TRUST_TOKEN_athm_v1();

  // Generate key with deployment A.
  uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_len, pub_key_len;
  ASSERT_TRUE(TRUST_TOKEN_generate_key_with_deployment_id(
      method, priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
      pub_key, &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0,
      kDeploymentIdA, sizeof(kDeploymentIdA) - 1));

  // Generate a separate key with deployment B for the client's public key.
  uint8_t priv_key_b[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key_b[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_b_len, pub_key_b_len;
  ASSERT_TRUE(TRUST_TOKEN_generate_key_with_deployment_id(
      method, priv_key_b, &priv_key_b_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
      pub_key_b, &pub_key_b_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0,
      kDeploymentIdB, sizeof(kDeploymentIdB) - 1));

  // Client uses deployment B key and context.
  bssl::UniquePtr<TRUST_TOKEN_CLIENT> client(
      TRUST_TOKEN_CLIENT_new(method, 10));
  ASSERT_TRUE(client);
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_set_deployment_id(
      client.get(), kDeploymentIdB, sizeof(kDeploymentIdB) - 1));
  size_t key_index;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_add_key(client.get(), &key_index, pub_key_b,
                                         pub_key_b_len));

  // Issuer uses deployment A key and context.
  bssl::UniquePtr<TRUST_TOKEN_ISSUER> issuer(
      TRUST_TOKEN_ISSUER_new(method, 10));
  ASSERT_TRUE(issuer);
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_set_deployment_id(
      issuer.get(), kDeploymentIdA, sizeof(kDeploymentIdA) - 1));
  ASSERT_TRUE(
      TRUST_TOKEN_ISSUER_add_key(issuer.get(), priv_key, priv_key_len));

  // Begin issuance (client uses deployment B's Z).
  uint8_t *issue_msg = nullptr, *issue_resp = nullptr;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 1));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);

  // Issuer signs with deployment A's key.
  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/0, /*private_metadata=*/0, /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_issue_resp(issue_resp);

  // Client tries to unblind with deployment B context - proof verification
  // should fail because the issuer used a different H.
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_FALSE(tokens);
}

TEST(TrustTokenTest, ATHMMultiKeySharedZ) {
  // Two keys with the same z, different (x,y,r_x,r_y). Issuance works with
  // either key.
  const TRUST_TOKEN_METHOD *method = TRUST_TOKEN_athm_v1_multikey();

  // Simplest test: generate one key, serialize it twice with different IDs.
  // That gives two keys with the same z (identical keys). This at least tests
  // that multi-key add_key works.
  uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_len, pub_key_len;
  ASSERT_TRUE(TRUST_TOKEN_generate_key_with_deployment_id(
      method, priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
      pub_key, &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0,
      nullptr, 0));

  // Create a copy with a different key ID.
  uint8_t priv_key2[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key2[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  OPENSSL_memcpy(priv_key2, priv_key, priv_key_len);
  OPENSSL_memcpy(pub_key2, pub_key, pub_key_len);
  // Overwrite the 4-byte key ID at the start.
  priv_key2[0] = 0;
  priv_key2[1] = 0;
  priv_key2[2] = 0;
  priv_key2[3] = 1;
  pub_key2[0] = 0;
  pub_key2[1] = 0;
  pub_key2[2] = 0;
  pub_key2[3] = 1;

  // Set up client with both keys.
  bssl::UniquePtr<TRUST_TOKEN_CLIENT> client(
      TRUST_TOKEN_CLIENT_new(method, 10));
  ASSERT_TRUE(client);
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_set_deployment_id(client.get(), nullptr, 0));
  size_t key_index;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_add_key(client.get(), &key_index, pub_key,
                                         pub_key_len));
  ASSERT_EQ(0u, key_index);
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_add_key(client.get(), &key_index, pub_key2,
                                         pub_key_len));
  ASSERT_EQ(1u, key_index);

  // Set up issuer with both keys.
  bssl::UniquePtr<TRUST_TOKEN_ISSUER> issuer(
      TRUST_TOKEN_ISSUER_new(method, 10));
  ASSERT_TRUE(issuer);
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_set_deployment_id(issuer.get(), nullptr, 0));
  ASSERT_TRUE(
      TRUST_TOKEN_ISSUER_add_key(issuer.get(), priv_key, priv_key_len));
  ASSERT_TRUE(
      TRUST_TOKEN_ISSUER_add_key(issuer.get(), priv_key2, priv_key_len));

  uint8_t metadata_key[32];
  RAND_bytes(metadata_key, sizeof(metadata_key));
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_set_metadata_key(issuer.get(), metadata_key,
                                                   sizeof(metadata_key)));

  // Issue with key 0 (public_metadata=0).
  uint8_t *issue_msg = nullptr, *issue_resp = nullptr;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 1));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/0, /*private_metadata=*/0, /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_issue_resp(issue_resp);
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_TRUE(tokens);
  ASSERT_EQ(1u, sk_TRUST_TOKEN_num(tokens.get()));
  EXPECT_EQ(0u, key_index);

  // Issue with key 1 (public_metadata=1).
  uint8_t *issue_msg2 = nullptr, *issue_resp2 = nullptr;
  size_t msg_len2, resp_len2;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg2,
                                                &msg_len2, 1));
  bssl::UniquePtr<uint8_t> free_issue_msg2(issue_msg2);
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp2, &resp_len2, &tokens_issued, issue_msg2,
      msg_len2, /*public_metadata=*/1, /*private_metadata=*/0,
      /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_issue_resp2(issue_resp2);
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens2(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp2,
                                         resp_len2));
  ASSERT_TRUE(tokens2);
  ASSERT_EQ(1u, sk_TRUST_TOKEN_num(tokens2.get()));
  EXPECT_EQ(1u, key_index);
}

TEST(TrustTokenTest, ATHMMultiKeyZMismatch) {
  // Two independently generated keys (different z). Second add_key should fail.
  const TRUST_TOKEN_METHOD *method = TRUST_TOKEN_athm_v1_multikey();

  uint8_t priv_key1[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key1[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key1_len, pub_key1_len;
  ASSERT_TRUE(TRUST_TOKEN_generate_key_with_deployment_id(
      method, priv_key1, &priv_key1_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
      pub_key1, &pub_key1_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0,
      nullptr, 0));

  uint8_t priv_key2[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key2[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key2_len, pub_key2_len;
  ASSERT_TRUE(TRUST_TOKEN_generate_key_with_deployment_id(
      method, priv_key2, &priv_key2_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
      pub_key2, &pub_key2_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 1,
      nullptr, 0));

  // Issuer: first key succeeds, second fails with Z_MISMATCH.
  bssl::UniquePtr<TRUST_TOKEN_ISSUER> issuer(
      TRUST_TOKEN_ISSUER_new(method, 10));
  ASSERT_TRUE(issuer);
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_set_deployment_id(issuer.get(), nullptr, 0));
  ASSERT_TRUE(
      TRUST_TOKEN_ISSUER_add_key(issuer.get(), priv_key1, priv_key1_len));
  ASSERT_FALSE(
      TRUST_TOKEN_ISSUER_add_key(issuer.get(), priv_key2, priv_key2_len));

  // Client: first key succeeds, second fails with Z_MISMATCH.
  bssl::UniquePtr<TRUST_TOKEN_CLIENT> client(
      TRUST_TOKEN_CLIENT_new(method, 10));
  ASSERT_TRUE(client);
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_set_deployment_id(client.get(), nullptr, 0));
  size_t key_index;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_add_key(client.get(), &key_index, pub_key1,
                                         pub_key1_len));
  ASSERT_FALSE(TRUST_TOKEN_CLIENT_add_key(client.get(), &key_index, pub_key2,
                                          pub_key2_len));
}

TEST(TrustTokenTest, ATHMMultiKeyRotation) {
  // Issue tokens with key 0, add key 1 (shared z), verify redemption works
  // for tokens from key 0.
  const TRUST_TOKEN_METHOD *method = TRUST_TOKEN_athm_v1_multikey();

  uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_len, pub_key_len;
  ASSERT_TRUE(TRUST_TOKEN_generate_key_with_deployment_id(
      method, priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
      pub_key, &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0,
      nullptr, 0));

  // Create key 1 with same z (same key bytes, different ID).
  uint8_t priv_key2[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key2[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  OPENSSL_memcpy(priv_key2, priv_key, priv_key_len);
  OPENSSL_memcpy(pub_key2, pub_key, pub_key_len);
  priv_key2[0] = 0;
  priv_key2[1] = 0;
  priv_key2[2] = 0;
  priv_key2[3] = 1;
  pub_key2[0] = 0;
  pub_key2[1] = 0;
  pub_key2[2] = 0;
  pub_key2[3] = 1;

  // Phase 1: Issue with only key 0.
  bssl::UniquePtr<TRUST_TOKEN_CLIENT> client(
      TRUST_TOKEN_CLIENT_new(method, 10));
  ASSERT_TRUE(client);
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_set_deployment_id(client.get(), nullptr, 0));
  size_t key_index;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_add_key(client.get(), &key_index, pub_key,
                                         pub_key_len));
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_add_key(client.get(), &key_index, pub_key2,
                                         pub_key_len));

  bssl::UniquePtr<TRUST_TOKEN_ISSUER> issuer(
      TRUST_TOKEN_ISSUER_new(method, 10));
  ASSERT_TRUE(issuer);
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_set_deployment_id(issuer.get(), nullptr, 0));
  ASSERT_TRUE(
      TRUST_TOKEN_ISSUER_add_key(issuer.get(), priv_key, priv_key_len));
  ASSERT_TRUE(
      TRUST_TOKEN_ISSUER_add_key(issuer.get(), priv_key2, priv_key_len));

  uint8_t metadata_key[32];
  RAND_bytes(metadata_key, sizeof(metadata_key));
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_set_metadata_key(issuer.get(), metadata_key,
                                                   sizeof(metadata_key)));

  // Issue token with key 0.
  uint8_t *issue_msg = nullptr, *issue_resp = nullptr;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 1));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/0, /*private_metadata=*/0, /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_issue_resp(issue_resp);
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_TRUE(tokens);
  ASSERT_EQ(1u, sk_TRUST_TOKEN_num(tokens.get()));

  // Redeem token issued by key 0.
  TRUST_TOKEN *token = sk_TRUST_TOKEN_value(tokens.get(), 0);
  uint8_t *redeem_msg = nullptr;
  size_t redeem_msg_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_redemption(
      client.get(), &redeem_msg, &redeem_msg_len, token, nullptr, 0, 0));
  bssl::UniquePtr<uint8_t> free_redeem_msg(redeem_msg);
  uint32_t public_value;
  uint8_t private_value;
  TRUST_TOKEN *rtoken;
  uint8_t *client_data;
  size_t client_data_len;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_redeem(issuer.get(), &public_value,
                                         &private_value, &rtoken, &client_data,
                                         &client_data_len, redeem_msg,
                                         redeem_msg_len));
  bssl::UniquePtr<TRUST_TOKEN> free_rtoken(rtoken);
  bssl::UniquePtr<uint8_t> free_client_data(client_data);
  EXPECT_EQ(0u, public_value);
}

}  // namespace
BSSL_NAMESPACE_END
