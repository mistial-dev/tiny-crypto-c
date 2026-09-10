/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "card_fixture.h"

static void assert_cleared(const ExampleCardKeyWorkspace* scratch)
{
  const uint8_t* bytes = (const uint8_t*)scratch;
  for (size_t i = 0; i < sizeof *scratch; ++i) munit_assert_uint(bytes[i], ==, 0);
}

typedef struct { uint8_t fascn[25]; int fail; } CancellationSource;

static TC_status cancellation_read(void* context, size_t position, TC_bytes* out)
{
  CancellationSource* source = context;
  if (source->fail || position) return TC_ERROR;
  *out = (TC_bytes){source->fascn,sizeof source->fascn};
  return TC_OK;
}

static void authentication_workflow(EVP_PKEY* key, TC_bytes leaf,
    const TC_X509_trust_anchor* anchor, const TC_X509_path_options* path,
    const TC_bytes* candidates, size_t candidate_count)
{
  enum { ACCEPTED, CANCELLED, STALE, UNAVAILABLE, BAD_SIGNATURE, EXPIRED,
    WRONG_PURPOSE, NO_WORK, BAD_PROOF, SOURCE_FAILURE, NO_READS, WRONG_ROOT,
    SUPERSEDED, NO_ANCHORS, MISSING_ISSUER, BAD_TIME, PRE_EPOCH };
  const uint64_t evaluation_time = UINT64_C(1788912000); /* 2026-09-09 UTC. */
  const ExampleTWICResult expected[] = {
    EXAMPLE_TWIC_AUTHENTICATED, EXAMPLE_TWIC_CANCELLED, EXAMPLE_TWIC_STALE,
    EXAMPLE_TWIC_UNAVAILABLE, EXAMPLE_TWIC_INVALID, EXAMPLE_TWIC_INVALID,
    EXAMPLE_TWIC_ERROR, EXAMPLE_TWIC_LIMIT, EXAMPLE_TWIC_INVALID,
    EXAMPLE_TWIC_ERROR, EXAMPLE_TWIC_LIMIT, EXAMPLE_TWIC_INVALID, EXAMPLE_TWIC_STALE,
    EXAMPLE_TWIC_INVALID, EXAMPLE_TWIC_INVALID, EXAMPLE_TWIC_ERROR, EXAMPLE_TWIC_ERROR
  };
  for (size_t scenario = 0; scenario < sizeof expected / sizeof *expected; ++scenario) {
    if (scenario == MISSING_ISSUER && !candidate_count) continue;
    CancellationSource source = {{0},0};
    memset(source.fascn,0xff,sizeof source.fascn);
    if (scenario == CANCELLED)
      memcpy(source.fascn,test_card_fascn,sizeof source.fascn);
    const TC_TWIC_CCL_source input = {&source,1,cancellation_read};
    const TC_bytes packed = {source.fascn,sizeof source.fascn};
    TC_TWIC_CCL_index index;
    TC_TWIC_CCL_snapshot slot = {0}, replacement = {0}, *held;
    TC_TWIC_CCL_store store = {0};
    const TC_TWIC_CCL_metadata metadata = {evaluation_time - 2,evaluation_time - 1};
    if (scenario == SOURCE_FAILURE)
      munit_assert_int(TC_TWIC_CCL_index_prepare(&input,1,&index), ==, TC_TWIC_CCL_OK);
    else
      munit_assert_int(TC_TWIC_CCL_index_from_memory(&packed,1,&index), ==, TC_TWIC_CCL_OK);
    munit_assert_int(TC_TWIC_CCL_store_prepare(&slot,&index,&metadata), ==, TC_TWIC_CCL_OK);
    munit_assert_int(TC_TWIC_CCL_store_publish(&store,0,&slot), ==, TC_TWIC_CCL_OK);
    munit_assert_int(TC_TWIC_CCL_store_acquire(&store,&held), ==, TC_TWIC_CCL_OK);
    SyntheticCard card = {0};
    card.key = key;
    card.algorithm = EXAMPLE_CARD_ALGORITHM_RSA_2048;
    card.mode = scenario == BAD_PROOF ? TAMPERED : NORMAL;
    if (scenario == SUPERSEDED) {
      const TC_TWIC_CCL_metadata newer = {evaluation_time,evaluation_time};
      munit_assert_int(TC_TWIC_CCL_store_prepare(&replacement,&index,&newer), ==, TC_TWIC_CCL_OK);
      card.replacement_store = &store;
      card.replacement = &replacement;
    }
    ExampleCardIO io = {transmit,&card,16,0};
    TC_X509_path_options options = *path;
    TC_X509_store_anchor trusted_anchor = {0};
    trusted_anchor.trust = *anchor;
    ExampleX509Source trusted = {candidates,candidate_count,&trusted_anchor,1};
    TC_X509_store_source trust = example_x509_source(&trusted);
    if (scenario == NO_ANCHORS) trust.anchor_count = 0;
    if (scenario == MISSING_ISSUER) trust.candidate_count = 0;
    uint8_t other_public_key[65];
    ExampleTWICRequest request = {leaf,&trust,&options,TC_TWIC_NEXGEN_CARD,0,
      held,10,evaluation_time - 2,1,EXAMPLE_CARD_RSA_V15};
    if (scenario == STALE) request.ccl_max_age = 1;
    if (scenario == UNAVAILABLE) request.ccl = NULL;
    if (scenario == EXPIRED) options.at.year = 2030;
    if (scenario == BAD_TIME) options.at.month = 13;
    if (scenario == PRE_EPOCH) options.at.year = 1969;
    if (scenario == WRONG_PURPOSE) options.purpose = (TC_bytes){NULL,0};
    if (scenario == SOURCE_FAILURE) source.fail = 1;
    if (scenario == NO_READS) request.ccl_reads = 0;
    if (scenario == WRONG_ROOT) {
      /* A different trusted key cannot verify the leaf's issuer signature. */
      EVP_PKEY* other = EVP_EC_gen("prime256v1");
      size_t length = 0;
      munit_assert_not_null(other);
      munit_assert_int(EVP_PKEY_get_octet_string_param(other,OSSL_PKEY_PARAM_PUB_KEY,
          other_public_key,sizeof other_public_key,&length), ==, 1);
      trusted_anchor.trust.public_key.key = (TC_bytes){other_public_key,length};
      EVP_PKEY_free(other);
    }
    uint8_t* mutable_leaf = (uint8_t*)leaf.data;
    if (scenario == BAD_SIGNATURE) mutable_leaf[leaf.length - 1] ^= 1;
    ExampleTWICWorkspace scratch;
    memset(&scratch,0xa5,sizeof scratch);
    Entropy entropy = {1,0,0};
    size_t work = scenario == NO_WORK ? 0 : WORK_LIMIT;
    const ExampleTWICResult result = example_twic_authenticate(&io,&request,
        random_digest,&entropy,&scratch,&work);
    if (scenario == BAD_SIGNATURE) mutable_leaf[leaf.length - 1] ^= 1;
    munit_assert_int(result, ==, expected[scenario]);
    if (scenario != ACCEPTED && scenario != BAD_PROOF && scenario != SUPERSEDED) {
      munit_assert_size(card.calls, ==, 0);
      munit_assert_size(entropy.calls, ==, 0);
    }
    if (scenario != WRONG_PURPOSE) {
      const uint8_t* bytes = (const uint8_t*)&scratch;
      for (size_t i = 0; i < sizeof scratch; ++i) munit_assert_uint(bytes[i], ==, 0);
    }
    munit_assert_int(TC_TWIC_CCL_store_release(held), ==, TC_TWIC_CCL_OK);
  }
}

static void validated_key(EVP_PKEY* card_key, const TC_X509_signature_provider* provider,
    uint8_t* encoded, size_t capacity, TC_X509_public_key* key)
{
  static const uint8_t card_auth_oid[] = {0x60,0x86,0x48,1,0x65,3,6,8};
  static const uint8_t client_auth_oid[] = {0x2b,6,1,5,5,7,3,2};
  static const uint8_t any_policy_oid[] = {0x55,0x1d,0x20,0};
  const TC_bytes any_policy = {any_policy_oid,sizeof any_policy_oid};
  EVP_PKEY* issuer_key = EVP_EC_gen("prime256v1");
  munit_assert_not_null(issuer_key);
  X509* issuer = make_certificate(issuer_key,"Synthetic card root",NULL);
  add_extension(issuer,NID_basic_constraints,"critical,CA:TRUE");
  add_extension(issuer,NID_key_usage,"critical,keyCertSign,cRLSign");
  X509* card = make_certificate(card_key,"Synthetic card authentication",issuer);
  add_extension(card,NID_basic_constraints,"critical,CA:FALSE");
  add_extension(card,NID_key_usage,"critical,digitalSignature");
  add_extension(card,NID_ext_key_usage,"2.16.840.1.101.3.6.8");
  uint8_t fascn[25];
  memcpy(fascn,test_card_fascn,sizeof fascn);
  static const char uuid_urn[] = "urn:uuid:91be2094-f6dc-5349-8000-4090e49e505c";
  uint8_t uuid[] = {0x91,0xbe,0x20,0x94,0xf6,0xdc,0x53,0x49,0x80,0,0x40,0x90,0xe4,0x9e,0x50,0x5c};
  add_card_identifiers(card,(TC_bytes){fascn,sizeof fascn},uuid_urn);
  uint8_t root_bytes[BUFFER_CAPACITY];
  const size_t root_length = encode_certificate(issuer,issuer_key,EVP_sha256(),root_bytes,sizeof root_bytes);
  const size_t card_length = encode_certificate(card,issuer_key,EVP_sha256(),encoded,capacity);
  ExampleX509Workspace storage;
  const TC_X509_path_workspace workspace = example_x509_workspace(&storage);
  TC_X509_workspace parser = {storage.frames,16,storage.oids,16};
  const TC_TLV_limits limits = {BUFFER_CAPACITY,BUFFER_CAPACITY,256,16};
  TC_X509_certificate root;
  munit_assert_int(TC_X509_read(root_bytes,root_length,&limits,&parser,&root), ==, TC_TLV_OK);
  const TC_X509_trust_anchor anchor = {root.subject,root.public_key};
  TC_X509_path_options options = {0};
  options.at = (TC_X509_time){2026,9,9,0,0,0};
  options.parsing = limits;
  options.max_certificates = 1;
  options.max_input = BUFFER_CAPACITY;
  options.max_work = WORK_LIMIT;
  options.signatures = *provider;
  options.initial_policies = &any_policy;
  options.initial_policy_count = 1;
  options.purpose = (TC_bytes){card_auth_oid,sizeof card_auth_oid};
  options.key_usage = TC_KEY_USAGE_DIGITAL_SIGNATURE;
  options.flags = TC_X509_PATH_REQUIRE_KEY_USAGE | TC_X509_PATH_REQUIRE_EXTENDED_KEY_USAGE |
      TC_X509_PATH_INHIBIT_ANY_PURPOSE;
  const TC_bytes leaf = {encoded,card_length};
  TC_X509_path_result result;
  munit_assert_int(TC_X509_path_validate(&leaf,1,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_VALID);
  *key = result.public_key;
  if (key->type == TC_KEY_RSA && key->bits == 2048) {
    authentication_workflow(card_key,leaf,&anchor,&options,NULL,0);
    /* Exercise the other registered purpose using independently signed DER. */
    static const uint8_t twic_auth_oid[] = {0x2b,6,1,4,1,0x81,0xe3,0x52,6,8};
    const int eku_index = X509_get_ext_by_NID(card,NID_ext_key_usage,-1);
    munit_assert_int(eku_index, >=, 0);
    X509_EXTENSION_free(X509_delete_ext(card,eku_index));
    add_extension(card,NID_ext_key_usage,"1.3.6.1.4.1.29138.6.8");
    uint8_t twic_encoded[BUFFER_CAPACITY];
    const size_t twic_length = encode_certificate(card,issuer_key,EVP_sha256(),twic_encoded,sizeof twic_encoded);
    TC_X509_path_options twic_options = options;
    twic_options.purpose = (TC_bytes){twic_auth_oid,sizeof twic_auth_oid};
    authentication_workflow(card_key,(TC_bytes){twic_encoded,twic_length},&anchor,&twic_options,NULL,0);

    EVP_PKEY* intermediate_key = EVP_EC_gen("prime256v1");
    munit_assert_not_null(intermediate_key);
    X509* intermediate = make_certificate(intermediate_key,"Synthetic card issuer",issuer);
    add_extension(intermediate,NID_basic_constraints,"critical,CA:TRUE,pathlen:0");
    add_extension(intermediate,NID_key_usage,"critical,keyCertSign,cRLSign");
    uint8_t intermediate_encoded[BUFFER_CAPACITY];
    const size_t intermediate_length = encode_certificate(intermediate,issuer_key,EVP_sha256(),
        intermediate_encoded,sizeof intermediate_encoded);
    munit_assert_int(X509_set_issuer_name(card,X509_get_subject_name(intermediate)), ==, 1);
    const size_t issued_length = encode_certificate(card,intermediate_key,EVP_sha256(),
        twic_encoded,sizeof twic_encoded);
    const TC_bytes candidate = {intermediate_encoded,intermediate_length};
    twic_options.max_certificates = 2;
    twic_options.max_input = 2 * BUFFER_CAPACITY;
    authentication_workflow(card_key,(TC_bytes){twic_encoded,issued_length},&anchor,
        &twic_options,&candidate,1);
    X509_free(intermediate);
    EVP_PKEY_free(intermediate_key);
  }

  TC_X509_certificate parsed_card;
  TC_TLV_reader extensions;
  TC_X509_extension extension;
  static const uint8_t san_oid[] = {0x55,0x1d,17};
  munit_assert_int(TC_X509_read(encoded,card_length,&limits,&parser,&parsed_card), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_extensions_init(&extensions,parsed_card.extensions.data,
      parsed_card.extensions.length,&limits), ==, TC_TLV_OK);
  unsigned found = 0;
  TC_TLV_result next;
  while ((next = TC_X509_extension_next(&extensions,&extension)) == TC_TLV_OK) {
    if (extension.oid.length != sizeof san_oid || memcmp(extension.oid.data,san_oid,sizeof san_oid)) continue;
    TC_PIV_card_identifiers identifiers;
    size_t work = WORK_LIMIT;
    munit_assert_int(TC_PIV_card_identifiers_read(extension.value,TC_TWIC_NEXGEN_CARD,
        &limits,storage.frames,16,&work,&identifiers), ==, TC_TLV_OK);
    int matched = -1;
    munit_assert_int(TC_PIV_card_identifiers_match(&identifiers,(TC_bytes){fascn,sizeof fascn},
        (TC_bytes){uuid,sizeof uuid},&work,&matched), ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 1);
    uint8_t csv[62];
    static const uint8_t hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof fascn; ++i) {
      csv[2 * i] = hex[fascn[i] >> 4];
      csv[2 * i + 1] = hex[fascn[i] & 15];
    }
    memcpy(csv + 2 * sizeof fascn,",01Sep2026\r\n",12);
    int listed = -1;
    munit_assert_int(TC_TWIC_CCL_contains((TC_bytes){csv,sizeof csv},identifiers.fascn,1,&listed), ==, TC_TWIC_CCL_OK);
    munit_assert_int(listed, ==, 1);
    csv[0] = 'f';
    munit_assert_int(TC_TWIC_CCL_contains((TC_bytes){csv,sizeof csv},identifiers.fascn,1,&listed), ==, TC_TWIC_CCL_OK);
    munit_assert_int(listed, ==, 0);
    fascn[0] ^= 1;
    munit_assert_int(TC_PIV_card_identifiers_match(&identifiers,(TC_bytes){fascn,sizeof fascn},
        (TC_bytes){uuid,sizeof uuid},&work,&matched), ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 0);
    fascn[0] ^= 1;
    uuid[15] ^= 1;
    munit_assert_int(TC_PIV_card_identifiers_match(&identifiers,(TC_bytes){fascn,sizeof fascn},
        (TC_bytes){uuid,sizeof uuid},&work,&matched), ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 0);
    uuid[15] ^= 1;
    ++found;
  }
  munit_assert_int(next, ==, TC_TLV_END);
  munit_assert_uint(found, ==, 1);

  options.purpose = (TC_bytes){client_auth_oid,sizeof client_auth_oid};
  munit_assert_int(TC_X509_path_validate(&leaf,1,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_INVALID);
  options.purpose = (TC_bytes){card_auth_oid,sizeof card_auth_oid};
  options.at.year = 2030;
  munit_assert_int(TC_X509_path_validate(&leaf,1,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_INVALID);
  options.at.year = 2026;
  encoded[card_length - 1] ^= 1;
  munit_assert_int(TC_X509_path_validate(&leaf,1,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_INVALID);
  encoded[card_length - 1] ^= 1;
  options.max_work = 0;
  munit_assert_int(TC_X509_path_validate(&leaf,1,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_LIMIT);
  X509_free(card);
  X509_free(issuer);
  EVP_PKEY_free(issuer_key);
}

static TC_status random_salt_failure(void* context, uint8_t* output, size_t length)
{
  Entropy* entropy = context;
  const TC_status result = random_digest(context,output,length);
  return entropy->calls == 2 ? TC_ERROR : result;
}

static MunitResult possession(const MunitParameter params[], void* context)
{
  const char* kind = munit_parameters_get(params,"key");
  const ExampleCardKeyReference reference = !strcmp(munit_parameters_get(params,"reference"),"9a") ?
      EXAMPLE_CARD_KEY_PIV_AUTHENTICATION : EXAMPLE_CARD_KEY_CARD_AUTHENTICATION;
  EVP_PKEY* generated;
  uint8_t algorithm;
  if (!strcmp(kind,"p256")) { generated = EVP_EC_gen("prime256v1"); algorithm = EXAMPLE_CARD_ALGORITHM_EC_P256; }
  else if (!strcmp(kind,"p384")) { generated = EVP_EC_gen("secp384r1"); algorithm = EXAMPLE_CARD_ALGORITHM_EC_P384; }
  else {
    const unsigned bits = !strcmp(kind,"rsa1024") ? 1024 : !strcmp(kind,"rsa2048") ? 2048 : 3072;
    generated = EVP_RSA_gen(bits);
    algorithm = bits == 1024 ? EXAMPLE_CARD_ALGORITHM_RSA_1024 : bits == 2048 ? EXAMPLE_CARD_ALGORITHM_RSA_2048 : EXAMPLE_CARD_ALGORITHM_RSA_3072;
  }
  munit_assert_not_null(generated);
  TC_ECDSA_workspace ec;
  TC_RSA_word words[TC_RSA_VERIFY_WORKSPACE_WORDS(3072)];
  const TC_RSA_workspace rsa = {words,sizeof words / sizeof *words};
  const TC_X509_native_workspace native = {&ec,&rsa,TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&native);
  uint8_t certificate[BUFFER_CAPACITY];
  TC_X509_public_key key;
  validated_key(generated,&provider,certificate,sizeof certificate,&key);
  if (key.type == TC_KEY_RSA) {
    uint8_t digest[32] = {0}, salt[32] = {1}, encoded[384], signature[384];
    const TC_RSA_pss_options options = {TC_HASH_SHA256,TC_HASH_SHA256,sizeof salt};
    TC_work_budget budget = {WORK_LIMIT};
    const size_t length = key.bits / 8;
    munit_assert_int(TC_RSA_encode_pss_digest(&options,(TC_bytes){digest,sizeof digest},
        (TC_bytes){salt,sizeof salt},(TC_buffer){encoded,length},&budget), ==, TC_RSA_OK);
    EVP_PKEY_CTX* signing = EVP_PKEY_CTX_new(generated,NULL);
    munit_assert_not_null(signing);
    munit_assert_int(EVP_PKEY_sign_init(signing), ==, 1);
    munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(signing,RSA_NO_PADDING), ==, 1);
    size_t signature_length = sizeof signature;
    munit_assert_int(EVP_PKEY_sign(signing,signature,&signature_length,encoded,length), ==, 1);
    EVP_PKEY_CTX_free(signing);
    EVP_PKEY_CTX* verifying = EVP_PKEY_CTX_new(generated,NULL);
    munit_assert_not_null(verifying);
    munit_assert_int(EVP_PKEY_verify_init(verifying), ==, 1);
    munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(verifying,RSA_PKCS1_PSS_PADDING), ==, 1);
    munit_assert_int(EVP_PKEY_CTX_set_signature_md(verifying,EVP_sha256()), ==, 1);
    munit_assert_int(EVP_PKEY_CTX_set_rsa_mgf1_md(verifying,EVP_sha256()), ==, 1);
    munit_assert_int(EVP_PKEY_CTX_set_rsa_pss_saltlen(verifying,sizeof salt), ==, 1);
    munit_assert_int(EVP_PKEY_verify(verifying,signature,signature_length,digest,sizeof digest), ==, 1);
    digest[0] ^= 1;
    munit_assert_int(EVP_PKEY_verify(verifying,signature,signature_length,digest,sizeof digest), !=, 1);
    EVP_PKEY_CTX_free(verifying);
    TC_key_challenge_options challenge_options = {0};
    challenge_options.signature.scheme = TC_SIGNATURE_RSA_PSS;
    challenge_options.signature.hash = TC_HASH_SHA256;
    challenge_options.signature.mgf_hash = TC_HASH_SHA256;
    challenge_options.signature.salt_length = sizeof salt;
    TC_key_challenge_workspace challenge_workspace;
    Entropy challenge_entropy = {1,0,0};
    TC_bytes challenge;
    /* A failed salt request clears the digest and leaves the output untouched. */
    memset(&challenge_workspace,0xa5,sizeof challenge_workspace);
    challenge = (TC_bytes){digest,sizeof digest};
    budget.remaining = WORK_LIMIT;
    munit_assert_int(TC_key_challenge_prepare(&key,&challenge_options,
        (TC_random_source){random_salt_failure,&challenge_entropy},&challenge_workspace,&budget,&challenge),
        ==, TC_KEY_CHALLENGE_ERROR);
    munit_assert_size(challenge_entropy.calls, ==, 2);
    munit_assert_ptr_equal(challenge.data,digest);
    munit_assert_size(challenge.length, ==, sizeof digest);
    const uint8_t* cleared = (const uint8_t*)&challenge_workspace;
    for (size_t i = 0; i < sizeof challenge_workspace; ++i)
      munit_assert_uint(cleared[i], ==, 0);
    /* Insufficient work is rejected before requesting randomness. */
    challenge_entropy = (Entropy){1,0,0};
    budget.remaining = (uint32_t)(length + sizeof digest + sizeof salt - 1);
    munit_assert_int(TC_key_challenge_prepare(&key,&challenge_options,
        (TC_random_source){random_digest,&challenge_entropy},&challenge_workspace,&budget,&challenge),
        ==, TC_KEY_CHALLENGE_LIMIT);
    munit_assert_size(challenge_entropy.calls, ==, 0);
    munit_assert_ptr_equal(challenge.data,digest);
    budget.remaining = WORK_LIMIT;
    munit_assert_int(TC_key_challenge_prepare(&key,&challenge_options,
        (TC_random_source){random_digest,&challenge_entropy},&challenge_workspace,&budget,&challenge),
        ==, TC_KEY_CHALLENGE_OK);
    munit_assert_size(challenge_entropy.calls, ==, 2);
    signing = EVP_PKEY_CTX_new(generated,NULL);
    munit_assert_not_null(signing);
    munit_assert_int(EVP_PKEY_sign_init(signing), ==, 1);
    munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(signing,RSA_NO_PADDING), ==, 1);
    signature_length = sizeof signature;
    munit_assert_int(EVP_PKEY_sign(signing,signature,&signature_length,challenge.data,challenge.length), ==, 1);
    EVP_PKEY_CTX_free(signing);
    budget.remaining = WORK_LIMIT;
    munit_assert_int(TC_key_challenge_verify(&key,(TC_bytes){signature,signature_length},
        &provider,&challenge_workspace,&budget), ==, TC_KEY_CHALLENGE_OK);
  }
  ExampleCardKeyWorkspace scratch;
  SyntheticCard card = {0};
  card.key = generated;
  card.algorithm = algorithm;
  card.reference = (uint8_t)reference;
  card.pss = !strcmp(munit_parameters_get(params,"padding"),"pss");
  Entropy entropy = {1,0,0};
  ExampleCardKeyPolicy policy = {
    TC_TWIC_LEGACY_CARD,TC_KEY_USAGE_DIGITAL_SIGNATURE,1,
    card.pss ? EXAMPLE_CARD_RSA_PSS : EXAMPLE_CARD_RSA_V15};
  const CardMode modes[] = {NORMAL,TAMPERED,REPLAY,WRONG_TAG,TRAILING,SIGN_LENGTH_ERROR,TRANSPORT_ERROR};
  const ExampleCardKeyResult outcomes[] = {EXAMPLE_CARD_KEY_VERIFIED,EXAMPLE_CARD_KEY_INVALID,
    EXAMPLE_CARD_KEY_INVALID,EXAMPLE_CARD_KEY_INVALID,EXAMPLE_CARD_KEY_INVALID,
    EXAMPLE_CARD_KEY_TRANSPORT,EXAMPLE_CARD_KEY_TRANSPORT};
  size_t normal_calls = 0;
  for (size_t i = 0; i < sizeof modes / sizeof *modes; ++i) {
    card.mode = modes[i];
    card.request_length = card.calls = 0;
    ExampleCardIO io = {transmit,&card,8,0};
    size_t work = WORK_LIMIT;
    memset(&scratch,0x5a,sizeof scratch);
    const size_t signatures = card.signatures;
    munit_assert_int(example_card_check_key(&io,reference,&key,&policy,&provider,random_digest,&entropy,&scratch,&work),
        ==, outcomes[i]);
    assert_cleared(&scratch);
    if (modes[i] == NORMAL) normal_calls = card.calls;
    if (modes[i] == SIGN_LENGTH_ERROR || modes[i] == TRANSPORT_ERROR) {
      munit_assert_int(io.stopped, ==, 1);
      munit_assert_size(card.signatures, ==, signatures);
      munit_assert_size(card.calls, ==, modes[i] == TRANSPORT_ERROR || key.bits < 2048 || key.type == TC_KEY_EC ? 1 : 2);
    } else munit_assert_size(card.signatures, ==, signatures + 1);
  }
  for (size_t step = 1; step <= normal_calls; ++step) {
    card.mode = NORMAL;
    card.request_length = card.calls = 0;
    card.fail_at = step;
    ExampleCardIO failed_io = {transmit,&card,8,0};
    size_t remaining = WORK_LIMIT;
    munit_assert_int(example_card_check_key(&failed_io,reference,&key,&policy,&provider,
        random_digest,&entropy,&scratch,&remaining), ==, EXAMPLE_CARD_KEY_TRANSPORT);
    munit_assert_int(failed_io.stopped, ==, 1);
    munit_assert_size(card.calls, ==, step);
    assert_cleared(&scratch);
  }
  card.fail_at = 0;
  for (size_t budget = 1; budget < normal_calls; ++budget) {
    card.mode = NORMAL;
    card.request_length = card.calls = 0;
    ExampleCardIO limited_io = {transmit,&card,budget,0};
    size_t remaining = WORK_LIMIT;
    munit_assert_int(example_card_check_key(&limited_io,reference,&key,&policy,&provider,
        random_digest,&entropy,&scratch,&remaining), ==, EXAMPLE_CARD_KEY_LIMIT);
    munit_assert_int(limited_io.stopped, ==, 1);
    munit_assert_size(card.calls, ==, budget);
    assert_cleared(&scratch);
  }
  if (normal_calls > 1) {
    card.mode = CHAIN_STATUS_ERROR;
    card.request_length = card.calls = 0;
    ExampleCardIO failed_io = {transmit,&card,8,0};
    size_t remaining = WORK_LIMIT;
    munit_assert_int(example_card_check_key(&failed_io,reference,&key,&policy,&provider,
        random_digest,&entropy,&scratch,&remaining), ==, EXAMPLE_CARD_KEY_INVALID);
    munit_assert_int(failed_io.stopped, ==, 1);
    munit_assert_size(card.calls, ==, 1);
    assert_cleared(&scratch);
  }
  /* RNG failure occurs before any card command and clears partial entropy. */
  card.calls = 0;
  ExampleCardIO io = {transmit,&card,8,0};
  size_t work = WORK_LIMIT;
  const size_t entropy_calls = entropy.calls;
  munit_assert_int(example_card_check_key(&io,(ExampleCardKeyReference)0,&key,&policy,
      &provider,random_digest,&entropy,&scratch,&work), ==, EXAMPLE_CARD_KEY_ERROR);
  munit_assert_size(card.calls, ==, 0);
  munit_assert_size(entropy.calls, ==, entropy_calls);
  munit_assert_size(work, ==, WORK_LIMIT);
  entropy.fail = 1;
  munit_assert_int(example_card_check_key(&io,reference,&key,&policy,&provider,random_digest,&entropy,&scratch,&work),
      ==, EXAMPLE_CARD_KEY_ERROR);
  munit_assert_size(card.calls, ==, 0);
  assert_cleared(&scratch);
  entropy.fail = 0;
  policy.allow_legacy_rsa1024 = 0;
  if (key.type == TC_KEY_RSA && key.bits == 1024) {
    work = WORK_LIMIT;
    munit_assert_int(example_card_check_key(&io,reference,&key,&policy,&provider,random_digest,&entropy,&scratch,&work),
        ==, EXAMPLE_CARD_KEY_UNSUPPORTED);
    munit_assert_size(card.calls, ==, 0);
    munit_assert_size(work, ==, WORK_LIMIT);
  }
  policy.profile = TC_TWIC_NEXGEN_CARD;
  card.mode = NORMAL;
  card.request_length = 0;
  work = WORK_LIMIT;
  const int nexgen = key.type == TC_KEY_RSA && key.bits == 2048;
  munit_assert_int(example_card_check_key(&io,reference,&key,&policy,&provider,random_digest,&entropy,&scratch,&work),
      ==, nexgen ? EXAMPLE_CARD_KEY_VERIFIED : EXAMPLE_CARD_KEY_UNSUPPORTED);
  if (!nexgen) munit_assert_size(card.calls, ==, 0);
  EVP_PKEY_free(generated);
  (void)context;
  return MUNIT_OK;
}

static MunitResult encoding(const MunitParameter params[], void* context)
{
  uint8_t digest[32] = {0}, encoded[384], saved[384];
  const TC_bytes input = {digest,sizeof digest};
  memset(encoded,0x5a,sizeof encoded);
  memcpy(saved,encoded,sizeof saved);
  TC_RSA_v15_options options = {TC_HASH_SHA256};
  TC_work_budget work = {255};
  munit_assert_int(TC_RSA_encode_v15_digest(&options,input,(TC_buffer){encoded,256},&work), ==, TC_RSA_LIMIT);
  munit_assert_memory_equal(sizeof encoded,encoded,saved);
  options.hash = TC_HASH_UNKNOWN; work.remaining = 256;
  munit_assert_int(TC_RSA_encode_v15_digest(&options,input,(TC_buffer){encoded,256},&work), ==, TC_RSA_UNSUPPORTED);
  options.hash = TC_HASH_SHA256;
  munit_assert_int(TC_RSA_encode_v15_digest(&options,input,(TC_buffer){encoded,127},&work), ==, TC_RSA_UNSUPPORTED);
  munit_assert_int(TC_RSA_encode_v15_digest(&options,(TC_bytes){digest,31},(TC_buffer){encoded,256},&work), ==, TC_RSA_ARGUMENT);
  munit_assert_int(TC_RSA_encode_v15_digest(&options,input,(TC_buffer){NULL,256},&work), ==, TC_RSA_ARGUMENT);
  munit_assert_int(TC_RSA_encode_v15_digest(&options,(TC_bytes){NULL,32},(TC_buffer){encoded,256},&work), ==, TC_RSA_ARGUMENT);
  munit_assert_int(TC_RSA_encode_v15_digest(&options,(TC_bytes){encoded,32},(TC_buffer){encoded,256},&work), ==, TC_RSA_ARGUMENT);
  munit_assert_int(TC_RSA_encode_v15_digest(&options,(TC_bytes){encoded + 255,32},(TC_buffer){encoded,256},&work), ==, TC_RSA_ARGUMENT);
  munit_assert_memory_equal(sizeof encoded,encoded,saved);
  for (size_t size = 128; size <= sizeof encoded; size += 128) {
    work.remaining = (uint32_t)size;
    munit_assert_int(TC_RSA_encode_v15_digest(&options,input,(TC_buffer){encoded,size},&work), ==, TC_RSA_OK);
    munit_assert_uint(encoded[0], ==, 0);
    munit_assert_uint(encoded[1], ==, 1);
    munit_assert_uint(encoded[size - 52], ==, 0);
    munit_assert_memory_equal(sizeof digest,encoded + size - sizeof digest,digest);
  }
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult pss_encoding(const MunitParameter params[], void* context)
{
  uint8_t digest[32] = {0}, salt[32] = {1}, encoded[384], expected[384];
  TC_RSA_pss_options options = {TC_HASH_SHA256,TC_HASH_SHA256,sizeof salt};
  const TC_bytes input = {digest,sizeof digest}, salt_bytes = {salt,sizeof salt};
  for (size_t length = 128; length <= sizeof encoded; length += 128) {
    TC_work_budget work = {WORK_LIMIT};
    munit_assert_int(TC_RSA_encode_pss_digest(&options,input,salt_bytes,
        (TC_buffer){expected,length},&work), ==, TC_RSA_OK);
    const uint32_t cost = WORK_LIMIT - work.remaining;
    munit_assert_uint(cost, >, 0);
    for (uint32_t budget = 0; budget <= cost; ++budget) {
      memset(encoded,0x5a,sizeof encoded);
      work.remaining = budget;
      const TC_RSA_result result = TC_RSA_encode_pss_digest(&options,input,salt_bytes,
          (TC_buffer){encoded,length},&work);
      if (budget == cost) {
        munit_assert_int(result, ==, TC_RSA_OK);
        munit_assert_memory_equal(length,encoded,expected);
        munit_assert_uint(work.remaining, ==, 0);
      } else {
        munit_assert_int(result, ==, TC_RSA_LIMIT);
        munit_assert_uint(work.remaining, <=, budget);
        const uint8_t fill = encoded[0];
        munit_assert_true(fill == 0 || fill == 0x5a);
        for (size_t i = 0; i < length; ++i) munit_assert_uint(encoded[i], ==, fill);
      }
      for (size_t i = length; i < sizeof encoded; ++i) munit_assert_uint(encoded[i], ==, 0x5a);
    }
  }
  enum { SHORT_SALT, NULL_SALT, OVERLAP_SALT, OVERLAP_DIGEST, UNKNOWN_HASH, BAD_SIZE };
  for (unsigned scenario = SHORT_SALT; scenario <= BAD_SIZE; ++scenario) {
    TC_bytes used_salt = salt_bytes, used_digest = input;
    TC_buffer output = {encoded,256};
    options.hash = scenario == UNKNOWN_HASH ? TC_HASH_UNKNOWN : TC_HASH_SHA256;
    if (scenario == SHORT_SALT) --used_salt.length;
    if (scenario == NULL_SALT) used_salt.data = NULL;
    if (scenario == OVERLAP_SALT) used_salt.data = encoded;
    if (scenario == OVERLAP_DIGEST) used_digest.data = encoded;
    if (scenario == BAD_SIZE) output.capacity = 255;
    memset(encoded,0x5a,sizeof encoded);
    TC_work_budget work = {WORK_LIMIT};
    munit_assert_int(TC_RSA_encode_pss_digest(&options,used_digest,used_salt,output,&work), ==,
      scenario == UNKNOWN_HASH || scenario == BAD_SIZE ? TC_RSA_UNSUPPORTED : TC_RSA_ARGUMENT);
    munit_assert_uint(work.remaining, ==, WORK_LIMIT);
    for (size_t i = 0; i < sizeof encoded; ++i) munit_assert_uint(encoded[i], ==, 0x5a);
  }
  (void)params; (void)context;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  static char* keys[] = {"rsa1024","rsa2048","rsa3072","p256","p384",NULL};
  static char* references[] = {"9a","9e",NULL};
  static char* padding[] = {"v15","pss",NULL};
  static MunitParameterEnum parameters[] = {{"key",keys},{"reference",references},{"padding",padding},{NULL,NULL}};
  MunitTest tests[] = {
    {"/possession",possession,NULL,NULL,MUNIT_TEST_OPTION_NONE,parameters},
    {"/encoding",encoding,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/pss-encoding",pss_encoding,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/card/authentication",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
