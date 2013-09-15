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
#include <unistd.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#define SSH_MAX_PUBKEY_BYTES 8192

extern char *optarg;
extern int optind;

BIO *in_bio, *out_bio;

void die_usage() {
    fprintf(stderr, "usage: ssh-smime [-h] [-i file] [-o file] ssh-pubkey1 [ssh-pubkey2] [...]\n");
    fprintf(stderr, "\nS/MIME encrypt input using ssh keys for recipients.\n");
    fprintf(stderr, "\nIf not specified, input and output default to stdin and stdout.\n");
    exit(2);
}

/*
 * Returns a list of public key files to read.
 */
char **parse_opts(int argc, char **argv)
{
    int ch;

    while ((ch = getopt(argc, argv, "hi:o:")) != -1) {
        switch (ch) {
            case 'i':
                in_bio = BIO_new_file(optarg, "r");
                if (!in_bio) err(1, "Unable to open file %s for reading: ", optarg);
                break;
            case 'o':
                out_bio = BIO_new_file(optarg, "w");
                if (!out_bio) err(1, "Unable to open file %s for writing: ", optarg);
                break;
            case 'h':
            case '?':
            default:
                die_usage();
            }
    }
    argc -= optind;
    argv += optind;

    // User didn't specify any recipients.
    if (!argc) die_usage();

    if (!in_bio) BIO_set_fp(in_bio, stdin, BIO_NOCLOSE);
    if (!out_bio) BIO_set_fp(out_bio, stdout, BIO_NOCLOSE);

    return argv;
}

// Boilerplate cert creation. Apparnetly openssl smime is not that picky about
// what the certs look like, so we don't even bother signing this.
X509 *gen_temp_cert(RSA *key)
{
    X509 *cert;
    EVP_PKEY *pk;
    X509_NAME *name = NULL;

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
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"ssh-smime", -1, -1,
                               0);

    X509_set_issuer_name(cert, name);

    return cert;
}

int base64_decode(char *key, char *inbuf)
{
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

// Silly buffer management routine to insure we always walk forward in the
// buffer and never walk past the end.
void *read_bytes(char *blob, int blobsize, int amount, int *offset, void *dest)
{
    void *r;
    if (*offset + amount > blobsize) errx(1, "Attempt to read past buffer");
    memcpy(dest, blob + *offset, amount);
    r = blob + *offset;
    *offset += amount;
    return r;
}

RSA *parse_ssh_pubkey(char *file, char *key, int keysize)
{
    unsigned long i;
    char buf[SSH_MAX_PUBKEY_BYTES];
    int offset = 0;
    RSA *rsa = RSA_new();

    if (!rsa) errx(1, "Could not allocate RSA");

    /*
     * The documentation states e and n will be allocated on a call to
     * BN_bin2bn if they are NULL. This doesn't seem to work, so allocate
     * them now.
     */
    rsa->e = BN_new();
    if (!rsa->e) errx(1, "Could not allocate BIGNUM");
    rsa->n = BN_new();
    if (!rsa->n) errx(1, "Could not allocate BUGNUM");

    // Read 4 bytes, the length of the key type name.
    read_bytes(key, keysize, 4, &offset, &i);
    i = ntohl(i);
    // Now read that many more bytes to read the key name itself.
    read_bytes(key, keysize, i, &offset, &buf);
    buf[i] = '\0';

    if (strcmp(buf, "ssh-rsa")) errx(1, "%s does not appear to contain an SSH RSA public key", file);

    // Same as above, for e.
    read_bytes(key, keysize, 4, &offset, &i);
    i = ntohl(i);
    read_bytes(key, keysize, i, &offset, &buf);
    if (BN_bin2bn((unsigned char *)buf, i, rsa->e) == NULL) errx(1, "buffer_get_bignum2_ret: BN_bin2bn failed");

    // Same as above, for n.
    read_bytes(key, keysize, 4, &offset, &i);
    i = ntohl(i);
    read_bytes(key, keysize, i, &offset, &buf);
    if (BN_bin2bn((unsigned char *)buf, i, rsa->n) == NULL) errx(1, "buffer_get_bignum2_ret: BN_bin2bn failed");

    return rsa;
}

RSA *read_ssh_pubkey(char *file)
{
    // Limit taken from SSH keygen
    char line[SSH_MAX_PUBKEY_BYTES + 1];
    char *key;
    char *comment;
    char decoded_key[SSH_MAX_PUBKEY_BYTES * 2];
    int decoded_size;

    FILE *f = fopen(file, "r");
    if (!f) err(1, "Failed to open file %s: ", file);
    fread(line, SSH_MAX_PUBKEY_BYTES, 1, f);
    if (ferror(f)) err(1, "Failed to read public key file %s: ", file);
    fclose(f);
    line[SSH_MAX_PUBKEY_BYTES] = '\0';

    /*
     * SSH public key files start with a string key type, followed by a space,
     * followed by the base64-encoded key material, followed by a comment. We
     * only care about the base64-encoded part.
     */
    key = strchr(line, ' ');
    if (!key) errx(1, "Public key file appears invalid");
    //line[key] = '\0'; // Line now contains just the key name.
    key++;
    if ((comment = strchr(key, ' '))) {
        *comment = '\0'; // We don't want the comment. Pretend we never read it.
    }

    decoded_size = base64_decode(key, decoded_key);
    return parse_ssh_pubkey(file, decoded_key, decoded_size);
}

STACK_OF(X509) *create_cert_stack(char **recipients)
{
    X509 *cert;
    STACK_OF(X509) *cert_stack = sk_X509_new_null();
    int i = 0;

    if (!cert_stack) err(1, "Failed to allocate certificate stack.");

    while(recipients[i]) {
        cert = gen_temp_cert(read_ssh_pubkey(recipients[i++]));
        if (!sk_X509_push(cert_stack, cert)) {
            err(1, "Failed to add certificate to stack");
        }
    }
    return cert_stack;
}

int main(int argc, char **argv)
{
    STACK_OF(X509) *recips = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = 1;
    int flags = CMS_BINARY;

    recips = create_cert_stack(parse_opts(argc, argv));

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* encrypt content */
    cms = CMS_encrypt(recips, in_bio, EVP_aes_256_cbc(), flags);

    if (!cms)
        goto err;

    /* Write out S/MIME message */
    if (!SMIME_write_CMS(out_bio, cms, in_bio, flags))
        goto err;

    ret = 0;

    err:

    if (ret) {
        fprintf(stderr, "Error Encrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    if (cms)
        CMS_ContentInfo_free(cms);

    sk_X509_pop_free(recips, X509_free);

    BIO_free(in_bio);
    BIO_free(out_bio);

    return ret;
}

