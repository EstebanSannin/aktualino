/* T1.2 verify: Ed25519 RFC 8032 vector (+tamper), and RSASSA-PSS-SHA256 with a
 * runtime-generated RSA-2048 key via openssl (+tamper). Also SHA-256 KAT. */
#include "akt_crypto.h"
#include "test_util.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static size_t read_file(const char *path, uint8_t *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    return n;
}

int main(void)
{
    /* --- SHA-256 known-answer: sha256("abc") --- */
    {
        uint8_t h[32];
        CHECK(akt_sha256("abc", 3, h) == 0);
        char hex[65];
        akt_hex_encode(h, 32, hex, sizeof(hex));
        CHECK_STREQ(hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    /* --- Ed25519 RFC 8032 Test 2 (1-byte message) --- */
    {
        uint8_t pub[32], sig[64], msg[1];
        size_t n;
        CHECK(akt_hex_decode(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            pub, sizeof(pub), &n) == 0 && n == 32);
        CHECK(akt_hex_decode(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            sig, sizeof(sig), &n) == 0 && n == 64);
        CHECK(akt_hex_decode("72", msg, sizeof(msg), &n) == 0 && n == 1);

        CHECK_MSG(akt_verify("ed25519", pub, 32, msg, 1, sig, 64) == true,
                  "RFC8032 positive");

        /* tamper signature */
        uint8_t bad[64]; memcpy(bad, sig, 64); bad[63] ^= 0x01;
        CHECK_MSG(akt_verify("ed25519", pub, 32, msg, 1, bad, 64) == false,
                  "RFC8032 tampered sig");
        /* tamper message */
        uint8_t badmsg[1] = { 0x73 };
        CHECK_MSG(akt_verify("ed25519", pub, 32, badmsg, 1, sig, 64) == false,
                  "RFC8032 tampered msg");
    }

    /* --- RSASSA-PSS-SHA256 with a fresh RSA-2048 key (openssl) --- */
    {
        const char *msg = "aktualino rsassa-pss-sha256 test message";
        size_t msg_len = strlen(msg);
        FILE *mf = fopen("/tmp/akt_msg.bin", "wb");
        CHECK(mf != NULL);
        if (mf) { fwrite(msg, 1, msg_len, mf); fclose(mf); }

        int r = 0;
        r |= system("openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 "
                    "-out /tmp/akt_rsa.pem 2>/dev/null");
        r |= system("openssl pkey -in /tmp/akt_rsa.pem -pubout "
                    "-out /tmp/akt_rsa_pub.pem 2>/dev/null");
        r |= system("openssl dgst -sha256 -sign /tmp/akt_rsa.pem "
                    "-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest "
                    "-out /tmp/akt_sig.bin /tmp/akt_msg.bin 2>/dev/null");
        CHECK_MSG(r == 0, "openssl RSA setup (rc=%d)", r);

        uint8_t pem[4096]; size_t pem_len = read_file("/tmp/akt_rsa_pub.pem", pem, sizeof(pem) - 1);
        pem[pem_len] = '\0';
        uint8_t sig[512]; size_t sig_len = read_file("/tmp/akt_sig.bin", sig, sizeof(sig));
        CHECK(pem_len > 0 && sig_len > 0);

        CHECK_MSG(akt_verify("rsassa-pss-sha256", pem, pem_len + 1,
                             msg, msg_len, sig, sig_len) == true,
                  "RSA-PSS positive (pem_len=%zu sig_len=%zu)", pem_len, sig_len);

        /* tamper signature */
        uint8_t bad[512]; memcpy(bad, sig, sig_len); bad[sig_len / 2] ^= 0x01;
        CHECK_MSG(akt_verify("rsassa-pss-sha256", pem, pem_len + 1,
                             msg, msg_len, bad, sig_len) == false,
                  "RSA-PSS tampered sig");
        /* tamper message */
        CHECK_MSG(akt_verify("rsassa-pss-sha256", pem, pem_len + 1,
                             "different message", 17, sig, sig_len) == false,
                  "RSA-PSS tampered msg");
    }

    /* --- method dispatch / unknown --- */
    {
        CHECK(akt_method_from_str("ed25519") == AKT_METHOD_ED25519);
        CHECK(akt_method_from_str("rsassa-pss-sha256") == AKT_METHOD_RSASSA_PSS_SHA256);
        CHECK(akt_method_from_str("ecPrime256v1") == AKT_METHOD_UNKNOWN);
        uint8_t d[32] = {0};
        CHECK(akt_verify("ecPrime256v1", d, 32, "x", 1, d, 32) == false);
    }

    TEST_SUMMARY("verify");
}
