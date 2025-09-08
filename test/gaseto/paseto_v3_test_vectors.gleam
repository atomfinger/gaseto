pub type PasetoV3LocalTestVector {
  PasetoV3LocalTestVector(
    name: String,
    key: String,
    nonce: String,
    token: String,
    payload: String,
    footer: String,
    implicit_assertion: String,
  )
}

pub type PasetoV3PublicTestVector {
  PasetoV3PublicTestVector(
    name: String,
    public_key: String,
    secret_key: String,
    token: String,
    payload: String,
    footer: String,
    implicit_assertion: String,
  )
}

pub type PasetoV3FailTestVector {
  PasetoV3FailTestVector(
    name: String,
    key: String,
    token: String,
    footer: String,
    implicit_assertion: String,
  )
}

pub const paseto_v3_local_test_vectors = [
  PasetoV3LocalTestVector(
    name: "3-E-1",
    key: "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    nonce: "0000000000000000000000000000000000000000000000000000000000000000",
    token: "v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAsRm2EsD6yBoZYn6cpVZNzSJOhSDN-sRaWjfLU-yn9OJH1J_B8GKtOQ9gSQlb8yk9Iza7teRdkiR89ZFyvPPsVjjFiepFUVcMa-LP18zV77f_crJrVXWa5PDNRkCSeHfBBeg",
    payload: "{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
    footer: "",
    implicit_assertion: "",
  ),
  PasetoV3LocalTestVector(
    name: "3-E-2",
    key: "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    nonce: "0000000000000000000000000000000000000000000000000000000000000000",
    token: "v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAqhWxBMDgyBoZYn6cpVZNzSJOhSDN-sRaWjfLU-yn9OJH1J_B8GKtOQ9gSQlb8yk9IzZfaZpReVpHlDSwfuygx1riVXYVs-UjcrG_apl9oz3jCVmmJbRuKn5ZfD8mHz2db0A",
    payload: "{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
    footer: "",
    implicit_assertion: "",
  ),
  PasetoV3LocalTestVector(
    name: "3-E-3",
    key: "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    nonce: "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
    token: "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlxnt5xyhQjFJomwnt7WW_7r2VT0G704ifult011-TgLCyQ2X8imQhniG_hAQ4BydM",
    payload: "{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
    footer: "",
    implicit_assertion: "",
  ),
  PasetoV3LocalTestVector(
    name: "3-E-4",
    key: "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    nonce: "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
    token: "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlBZa_gOpVj4gv0M9lV6Pwjp8JS_MmaZaTA1LLTULXybOBZ2S4xMbYqYmDRhh3IgEk",
    payload: "{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
    footer: "",
    implicit_assertion: "",
  ),
  PasetoV3LocalTestVector(
    name: "3-E-5",
    key: "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    nonce: "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
    token: "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlkYSIbXOgVuIQL65UMdW9WcjOpmqvjqD40NNzed-XPqn1T3w-bJvitYpUJL_rmihc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
    payload: "{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
    footer: "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}",
    implicit_assertion: "",
  ),
  PasetoV3LocalTestVector(
    name: "3-E-6",
    key: "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    nonce: "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
    token: "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJmSeEMphEWHiwtDKJftg41O1F8Hat-8kQ82ZIAMFqkx9q5VkWlxZke9ZzMBbb3Znfo.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
    payload: "{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
    footer: "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}",
    implicit_assertion: "",
  ),
  PasetoV3LocalTestVector(
    name: "3-E-7",
    key: "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    nonce: "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
    token: "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJkzWACWAIoVa0bz7EWSBoTEnS8MvGBYHHo6t6mJunPrFR9JKXFCc0obwz5N-pxFLOc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
    payload: "{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
    footer: "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}",
    implicit_assertion: "{\"test-vector\":\"3-E-7\"}",
  ),
  PasetoV3LocalTestVector(
    name: "3-E-8",
    key: "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    nonce: "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
    token: "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJmZHSSKYR6AnPYJV6gpHtx6dLakIG_AOPhu8vKexNyrv5_1qoom6_NaPGecoiz6fR8.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
    payload: "{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
    footer: "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}",
    implicit_assertion: "{\"test-vector\":\"3-E-8\"}",
  ),
  PasetoV3LocalTestVector(
    name: "3-E-9",
    key: "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    nonce: "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
    token: "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlk1nli0_wijTH_vCuRwckEDc82QWK8-lG2fT9wQF271sgbVRVPjm0LwMQZkvvamqU.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24",
    payload: "{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
    footer: "arbitrary-string-that-isn't-json",
    implicit_assertion: "{\"test-vector\":\"3-E-9\"}",
  ),
]

pub const paseto_v3_public_test_vectors = [
  PasetoV3PublicTestVector(
    name: "3-S-1",
    public_key: "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
    secret_key: "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96",
    token: "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9vrarT0tBPumLsUh5iJGDDH7sIkPk1fW8Ej6R2j-8jB7rkkCJyEKxcMNPJ5jLurPvZSzRdLb-Ia_Y2YXavY77xbLzJQJkA_zjJeYrd8mWQ24oOpkts1Css3Xa74cz_j3A",
    payload: "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
    footer: "",
    implicit_assertion: "",
  ),
  PasetoV3PublicTestVector(
    name: "3-S-2",
    public_key: "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
    secret_key: "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96",
    token: "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9ZWrbGZ6L0MDK72skosUaS0Dz7wJ_2bMcM6tOxFuCasO9GhwHrvvchqgXQNLQQyWzGC2wkr-VKII71AvkLpC8tJOrzJV1cap9NRwoFzbcXjzMZyxQ0wkshxZxx8ImmNWP.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9",
    payload: "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
    footer: "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}",
    implicit_assertion: "",
  ),
  PasetoV3PublicTestVector(
    name: "3-S-3",
    public_key: "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
    secret_key: "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96",
    token: "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9FrkqK6FaB39LisqmPmIHLnu5P8zBTdO_EyWqeworXkGMBChHk-ZZWPt2r7qSYpOqWmvf0oBgf9Elx1TKS4a3YKIcaYddPlu6B9w5LT_b76sCqdVDjE5bH8ZgvZ708c48.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9",
    payload: "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
    footer: "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}",
    implicit_assertion: "{\"test-vector\":\"3-S-3\"}",
  ),
]

// F-vectors: tokens that should fail to decrypt/verify.
// key field holds the local hex key (for local tokens) or public-key hex (for F-1 which has a public key).
pub const paseto_v3_fail_test_vectors = [
  // 3-F-1: v3.local token but public key provided (wrong key size for local)
  PasetoV3FailTestVector(
    name: "3-F-1",
    key: "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
    token: "v3.local.tthw-G1Da_BzYeMu_GEDp-IyQ7jzUCQHxCHRdDY6hQjKg6CuxECXfjOzlmNgNJ-WELjN61gMDnldG9OLkr3wpxuqdZksCzH9Ul16t3pXCLGPoHQ9_l51NOqVmMLbFVZOPhsmdhef9RxJwmqvzQ_Mo_JkYRlrNA.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24",
    footer: "arbitrary-string-that-isn't-json",
    implicit_assertion: "{\"test-vector\":\"3-F-1\"}",
  ),
  // 3-F-2: v3.public token but local key provided (wrong key size for public)
  PasetoV3FailTestVector(
    name: "3-F-2",
    key: "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    token: "v3.public.eyJpbnZhbGlkIjoidGhpcyBzaG91bGQgbmV2ZXIgZGVjb2RlIn1hbzIBD_EU54TYDTvsN9bbCU1QPo7FDeIhijkkcB9BrVH73XyM3Wwvu1pJaGCOEc0R5DVe9hb1ka1cYBd0goqVHt0NQ2NhPtILz4W36eCCqyU4uV6xDMeLI8ni6r3GnaY.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
    footer: "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
    implicit_assertion: "{\"test-vector\":\"3-F-2\"}",
  ),
  // 3-F-3: v4.local token (wrong version - not implemented)
  PasetoV3FailTestVector(
    name: "3-F-3",
    key: "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    token: "v4.local.1JgN1UG8TFAYS49qsx8rxlwh-9E4ONUm3slJXYi5EibmzxpF0Q-du6gakjuyKCBX8TvnSLOKqCPu8Yh3WSa5yJWigPy33z9XZTJF2HQ9wlLDPtVn_Mu1pPxkTU50ZaBKblJBufRA.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24",
    footer: "arbitrary-string-that-isn't-json",
    implicit_assertion: "{\"test-vector\":\"3-F-3\"}",
  ),
  // 3-F-4: v3.local token with corrupted HMAC tag (last base64 char changed from g to h)
  PasetoV3FailTestVector(
    name: "3-F-4",
    key: "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    token: "v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAsRm2EsD6yBoZYn6cpVZNzSJOhSDN-sRaWjfLU-yn9OJH1J_B8GKtOQ9gSQlb8yk9Iza7teRdkiR89ZFyvPPsVjjFiepFUVcMa-LP18zV77f_crJrVXWa5PDNRkCSeHfBBeh",
    footer: "",
    implicit_assertion: "",
  ),
  // 3-F-5: v3.local token with illegal padding character '=' in base64url
  PasetoV3FailTestVector(
    name: "3-F-5",
    key: "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
    token: "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlkYSIbXOgVuIQL65UMdW9WcjOpmqvjqD40NNzed-XPqn1T3w-bJvitYpUJL_rmihc=.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
    footer: "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}",
    implicit_assertion: "",
  ),
]
