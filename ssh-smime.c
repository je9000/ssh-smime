/*
 * ssh-smime - S/MIME file encryption with SSH public keys.
 *
 * Copyright John Eaglesham, 2013
 *
 * Based on the OpenSSL Simple S/MIME encrypt example.
 *
 * This utility is licensed under the same terms as OpenSSL itself.
 */

#include <stdio.h>
#include <err.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <netinet/in.h>

#define SSH_MAX_PUBKEY_BYTES 8192

X509 *gen_temp_cert(RSA *key) {
    X509 *cert;
    EVP_PKEY *pk;
    X509_NAME *name = NULL;
    X509_NAME_ENTRY *ne = NULL;
    X509_EXTENSION *ex = NULL;

    if ((pk = EVP_PKEY_new()) == NULL) errx(1, "Failed to allocate pubkey");

    if ((cert = X509_new()) == NULL) errx(1, "Failed to allocate cert");

    if (!EVP_PKEY_assign_RSA(pk, key)) errx(1, "Failed to assign key");

    X509_set_version(cert, 3);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), (long)60*60);
    X509_set_pubkey(cert, pk);

    name = X509_get_subject_name(cert);

    /* This function creates and adds the entry, working out the
     * correct string type and performing checks on its length.
     * Normally we'd check the return value for errors...
     */
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, "US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, "ssh-smime", -1, -1,
                               0);

    X509_set_issuer_name(cert, name);

    return cert;
}

int base64_decode(char *key, char *inbuf) {
    BIO *bio, *b64;
    int inlen;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(key, -1);
    bio = BIO_push(b64, bio);
    inlen = BIO_read(bio, inbuf, SSH_MAX_PUBKEY_BYTES);

    BIO_free_all(bio);

    return inlen;
}

void *read_bytes(char *blob, int blobsize, int amount, int *offset, void *dest) {
    void *r;
    if (*offset + amount > blobsize) errx(1, "Attempt to read past buffer");
    memcpy(dest, blob + *offset, amount);
    r = blob + *offset;
    *offset += amount;
    return r;
}

RSA *parse_ssh_pubkey(char *file, char *key, int keysize) {
    unsigned long i;
    char buf[SSH_MAX_PUBKEY_BYTES];
    int offset = 0;
    RSA *rsa = RSA_new();

    if (!rsa) err(1, "Could not allocate RSA");

    /*
     * The documentation states e and n will be allocated on a call to
     * BN_bin2bn if they are NULL. This doesn't seem to work, so allocate
     * them now.
     */
    rsa->e = BN_new();
    if (!rsa->e) err(1, "Could not allocate BIGNUM");
    rsa->n = BN_new();
    if (!rsa->n) err(1, "Could not allocate BUGNUM");

    read_bytes(key, keysize, 4, &offset, &i);
    i = ntohl(i);
    fprintf(stderr, "Key type name length: %i\n", i);
    read_bytes(key, keysize, i, &offset, &buf);
    buf[i] = '\0';
    fprintf(stderr, "Key type: %s\n", buf);

    if (strcmp(buf, "ssh-rsa")) err(1, "%s does not appear to contain an SSH RSA public key", file);

    read_bytes(key, keysize, 4, &offset, &i);
    i = ntohl(i);
    fprintf(stderr, "e length: %i\n", i);
    read_bytes(key, keysize, i, &offset, &buf);

    if (BN_bin2bn(buf, i, rsa->e) == NULL) err(1, "buffer_get_bignum2_ret: BN_bin2bn failed");

    read_bytes(key, keysize, 4, &offset, &i);
    i = ntohl(i);
    fprintf(stderr, "n length: %i\n", i);
    read_bytes(key, keysize, i, &offset, &buf);
    if (BN_bin2bn(buf, i, rsa->n) == NULL) err(1, "buffer_get_bignum2_ret: BN_bin2bn failed");

    return rsa;
}

RSA *read_ssh_pubkey(char *file) {
    RSA *pubkey;
    char line[SSH_MAX_PUBKEY_BYTES + 1]; // ssh-keygen has this limit too
    char *key;
    char *comment;
    char decoded_key[SSH_MAX_PUBKEY_BYTES * 2];
    int decoded_size;

    FILE *f = fopen(file, "r");
    if (!f) err(1, "Failed to open file %s", file);
    fread(line, SSH_MAX_PUBKEY_BYTES, 1, f);
    if (ferror(f)) err(1, "Failed to read public key file");
    fclose(f);
    line[SSH_MAX_PUBKEY_BYTES] = '\0';
    key = strchr(line, ' ');
    if (!key) errx(1, "Public key file appears invalid");
    //line[key] = '\0'; // Line now contains just the key name.
    key++;
    if ((comment = strchr(key, ' '))) {
        *comment = '\0'; // We don't care about the comment. Pretend we never read it.
    }
    decoded_size = base64_decode(key, &decoded_key);
    return parse_ssh_pubkey(file, decoded_key, decoded_size);
}

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    X509 *rcert = NULL;
    STACK_OF(X509) *recips = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = 1;

    /*
     * On OpenSSL 1.0.0 and later only:
     * for streaming set CMS_STREAM
     */
    int flags = CMS_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    rcert = gen_temp_cert(read_ssh_pubkey("testkey.pub"));

    if (!rcert)
        goto err;

    /* Create recipient STACK and add recipient cert to it */
    recips = sk_X509_new_null();

    if (!recips || !sk_X509_push(recips, rcert))
        goto err;

    /* sk_X509_pop_free will free up recipient STACK and its contents
     * so set rcert to NULL so it isn't freed up twice.
     */
    rcert = NULL;

    /* Open content being encrypted */

    in = BIO_new_file("encr.txt", "r");

    if (!in)
        goto err;

    /* encrypt content */
    cms = CMS_encrypt(recips, in, EVP_des_ede3_cbc(), flags);

    if (!cms)
        goto err;

    out = BIO_new_file("smencr.txt", "w");
    if (!out)
        goto err;

    /* Write out S/MIME message */
    if (!SMIME_write_CMS(out, cms, in, flags))
        goto err;

    ret = 0;

    err:

    if (ret) {
        fprintf(stderr, "Error Encrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    if (cms)
        CMS_ContentInfo_free(cms);
    if (rcert)
        X509_free(rcert);
    if (recips)
        sk_X509_pop_free(recips, X509_free);

    if (in)
        BIO_free(in);
    if (out)
        BIO_free(out);

    return ret;
}

