#include "h/config.h"

#ifdef HAVE_LIBSSL
#ifdef HAVE_LIBCRYPTO
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#ifdef HAVE_LIBNGHTTP2
#include <nghttp2/nghttp2.h>
#endif
#include <assert.h>

#include "h/proto.h"

/**
Password for out certificate.
*/
static const char psswd[] = "password";

/**
Certificate stored in memory.
*/
static const char xxx[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIICGDCCAYECAgEBMA0GCSqGSIb3DQEBBAUAMFcxCzAJBgNVBAYTAlVTMRMwEQYD\n"
	"VQQKEwpSVEZNLCBJbmMuMRkwFwYDVQQLExBXaWRnZXRzIERpdmlzaW9uMRgwFgYD\n"
	"VQQDEw9UZXN0IENBMjAwMTA1MTcwHhcNMDEwNTE3MTYxMDU5WhcNMDQwMzA2MTYx\n"
	"MDU5WjBRMQswCQYDVQQGEwJVUzETMBEGA1UEChMKUlRGTSwgSW5jLjEZMBcGA1UE\n"
	"CxMQV2lkZ2V0cyBEaXZpc2lvbjESMBAGA1UEAxMJbG9jYWxob3N0MIGfMA0GCSqG\n"
	"SIb3DQEBAQUAA4GNADCBiQKBgQCiWhMjNOPlPLNW4DJFBiL2fFEIkHuRor0pKw25\n"
	"J0ZYHW93lHQ4yxA6afQr99ayRjMY0D26pH41f0qjDgO4OXskBsaYOFzapSZtQMbT\n"
	"97OCZ7aHtK8z0ZGNW/cslu+1oOLomgRxJomIFgW1RyUUkQP1n0hemtUdCLOLlO7Q\n"
	"CPqZLQIDAQABMA0GCSqGSIb3DQEBBAUAA4GBAIumUwl1OoWuyN2xfoBHYAs+lRLY\n"
	"KmFLoI5+iMcGxWIsksmA+b0FLRAN43wmhPnums8eXgYbDCrKLv2xWcvKDP3mps7m\n"
	"AMivwtu/eFpYz6J8Mo1fsV4Ys08A/uPXkT23jyKo2hMu8mywkqXCXYF2e+7pEeBr\n"
	"dsbmkWK5NgoMl8eM\n"
	"-----END CERTIFICATE-----"
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"Proc-Type: 4,ENCRYPTED\n"
	"DEK-Info: DES-EDE3-CBC,5772A2A7BE34B611\n"
	"\n"
	"1yJ+xAn4MudcIfXXy7ElYngJ9EohIh8yvcyVLmE4kVd0xeaL/Bqhvk25BjYCK5d9\n"
	"k1K8cjgnKEBjbC++0xtJxFSbUhwoKTLwn+sBoJDcFzMKkmJXXDbSTOaNr1sVwiAR\n"
	"SnB4lhUcHguYoV5zlRJn53ft7t1mjB6RwGH+d1Zx6t95OqM1lnKqwekwmotVAWHj\n"
	"ncu3N8qhmoPMppmzEv0fOo2/pK2WohcJykSeN5zBrZCUxoO0NBNEZkFUcVjR+KsA\n"
	"1ZeI1mU60szqg+AoU/XtFcow8RtG1QZKQbbXzyfbwaG+6LqkHaWYKHQEI1546yWK\n"
	"us1HJ734uUkZoyyyazG6PiGCYV2u/aY0i3qdmyDqTvmVIvve7E4glBrtDS9h7D40\n"
	"nPShIvOatoPzIK4Y0QSvrI3G1vTsIZT3IOZto4AWuOkLNfYS2ce7prOreF0KjhV0\n"
	"3tggw9pHdDmTjHTiIkXqheZxZ7TVu+pddZW+CuB62I8lCBGPW7os1f21e3eOD/oY\n"
	"YPCI44aJvgP+zUORuZBWqaSJ0AAIuVW9S83Yzkz/tlSFHViOebyd8Cug4TlxK1VI\n"
	"q6hbSafh4C8ma7YzlvqjMzqFifcIolcbx+1A6ot0UiayJTUra4d6Uc4Rbc9RIiG0\n"
	"jfDWC6aii9YkAgRl9WqSd31yASge/HDqVXFwR48qdlYQ57rcHviqxyrwRDnfw/lX\n"
	"Mf6LPiDKEco4MKej7SR2kK2c2AgxUzpGZeAY6ePyhxbdhA0eY21nDeFd/RbwSc5s\n"
	"eTiCCMr41OB4hfBFXKDKqsM3K7klhoz6D5WsgE6u3lDoTdz76xOSTg==\n"
	"-----END RSA PRIVATE KEY-----\n"
	"";

static BIO *bio_err = NULL;
static SSL_CTX *ctx = NULL;
static int certs_loaded = 0;

/**
Helper function for "reading" of the password.
Useful when some wants to allow user
to enter password by hand.

Does nothing interesting in our case, simply copies password.
*/
static int password_cb(char *buf, int size, int rwflag, void *password) {
	strncpy(buf, (char *)(password), size);
	buf[size - 1] = 0;
	return(strlen(buf));
}

/**
Create BIO output file handler for standard error output.
*/
static int berr_exit(const char *string) {
	BIO_printf(bio_err, "%s\n", string);
	ERR_print_errors(bio_err);
	exit(1);
}

static void nodes_print(const char *name, STACK_OF(X509_POLICY_NODE) *nodes)
{
    X509_POLICY_NODE *node;
    int i;

    BIO_printf(bio_err, "%s Policies:", name);
    if (nodes) {
        BIO_puts(bio_err, "\n");
        for (i = 0; i < sk_X509_POLICY_NODE_num(nodes); i++) {
            node = sk_X509_POLICY_NODE_value(nodes, i);
            X509_POLICY_NODE_print(bio_err, node, 2);
        }
    } else
        BIO_puts(bio_err, " <empty>\n");
}


static void policies_print(X509_STORE_CTX *ctx)
{
    X509_POLICY_TREE *tree;
    int explicit_policy;
    tree = X509_STORE_CTX_get0_policy_tree(ctx);
    explicit_policy = X509_STORE_CTX_get_explicit_policy(ctx);

    BIO_printf(bio_err, "Require explicit Policy: %s\n",
               explicit_policy ? "True" : "False");
    
    nodes_print("Authority", X509_policy_tree_get0_policies(tree));
    nodes_print("User", X509_policy_tree_get0_user_policies(tree));
}


static int verify_callback(int ok, X509_STORE_CTX *ctx)
{
	if (debug) {
		X509 *err_cert;
		int err, depth;

		err_cert = X509_STORE_CTX_get_current_cert(ctx);
		err = X509_STORE_CTX_get_error(ctx);
		depth = X509_STORE_CTX_get_error_depth(ctx);

		BIO_printf(bio_err, "depth=%d ", depth);
		if (err_cert) {
			X509_NAME_print_ex(bio_err,
							   X509_get_subject_name(err_cert),
							   0, XN_FLAG_ONELINE);
			BIO_puts(bio_err, "\n");
		} else
			BIO_puts(bio_err, "<no cert>\n");

		if (!ok) {
			BIO_printf(bio_err, "verify error:num=%d:%s\n", err,
					   X509_verify_cert_error_string(err));
		}
		switch (err) {
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			BIO_puts(bio_err, "issuer: ");
			X509_NAME_print_ex(bio_err, X509_get_issuer_name(err_cert),
							   0, XN_FLAG_ONELINE);
			BIO_puts(bio_err, "\n");
			break;
		case X509_V_ERR_CERT_NOT_YET_VALID:
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
			BIO_printf(bio_err, "notBefore=");
			ASN1_TIME_print(bio_err, X509_get_notBefore(err_cert));
			BIO_printf(bio_err, "\n");
			break;
		case X509_V_ERR_CERT_HAS_EXPIRED:
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
			BIO_printf(bio_err, "notAfter=");
			ASN1_TIME_print(bio_err, X509_get_notAfter(err_cert));
			BIO_printf(bio_err, "\n");
			break;
		case X509_V_ERR_NO_EXPLICIT_POLICY:
			policies_print(ctx);
			break;
		}
		if (err == X509_V_OK && ok == 2)
			policies_print(ctx);
		if (ok)
			BIO_printf(bio_err, "verify return:%d\n", ok);
	}

    return (ok);
}

#ifdef HAVE_LIBNGHTTP2
/**
 * The NPN callback is used by the client to select the next application protocol over TLS
 */
static int select_next_proto_cb(SSL *ssl, unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg) {
	mcrawler_url *url = (mcrawler_url *)SSL_get_app_data(ssl);
	if (url->options & 1<<MCURL_OPT_DISABLE_HTTP2) {
		// only http/1.1 is suppported
		const unsigned char client[] = "\x8http/1.1";
		unsigned int client_len = sizeof(client) - 1;
		if (OPENSSL_NPN_NEGOTIATED == SSL_select_next_proto(
					out, outlen, in, inlen, client, client_len
					)
				) {
			return SSL_TLSEXT_ERR_OK;
		}
		return SSL_TLSEXT_ERR_OK;
	} else {
		if (-1 == nghttp2_select_next_protocol(out, outlen, in, inlen)) {
			return SSL_TLSEXT_ERR_NOACK;
		}
		return SSL_TLSEXT_ERR_OK;
	}
}
#endif

/**
Returns valid SSL context.
When call for the first time, then initialize SSL and the context itself.
*/
static SSL_CTX *mossad() {
	if (ctx) {
		return ctx;
	}
	if(!bio_err){
		/* Global system initialization*/
		SSL_library_init();
		SSL_load_error_strings();

		/* An error write context */
		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	}

	/* Create our context*/
	const SSL_METHOD *meth = SSLv23_method();
	ctx = SSL_CTX_new(meth);

	X509 *cert = NULL;
	RSA *rsa = NULL;
	BIO *cbio, *kbio;
	
	cbio = BIO_new_mem_buf((void*)xxx, sizeof(cert));
	cert = PEM_read_bio_X509(cbio, NULL, password_cb, (void*)psswd);
	BIO_free(cbio);
	if (cert != NULL) {
		berr_exit("Can't read certificate from memory");
	}
	SSL_CTX_use_certificate(ctx, cert);

	kbio = BIO_new_mem_buf((void*)xxx, -1);
	rsa = PEM_read_bio_RSAPrivateKey(kbio, NULL, password_cb, (void*)psswd);
	BIO_free(kbio);
	if (rsa != NULL) {
		berr_exit("Can't read key from memory");
	}
	SSL_CTX_use_RSAPrivateKey(ctx, rsa);

	// test here https://badssl.com/
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

#ifdef HAVE_LIBNGHTTP2
	SSL_CTX_set_next_proto_select_cb(ctx, select_next_proto_cb, NULL);
#endif
	return ctx;
}

static void load_verify_locations() {
	if (certs_loaded) {
		return;
	}
	certs_loaded = 1;

#ifdef CA_BUNDLE
# ifdef CA_PATH
	debugf("CA bundle: %s\n", CA_BUNDLE);
	debugf("CA path: %s\n", CA_PATH);
	if (!SSL_CTX_load_verify_locations(ctx, CA_BUNDLE, CA_PATH)) {
		ERR_print_errors(bio_err);
	}
# else
	debugf("CA bundle: %s\n", CA_BUNDLE);
	if (!SSL_CTX_load_verify_locations(ctx, CA_BUNDLE, NULL)) {
		ERR_print_errors(bio_err);
	}
# endif
#else
# ifdef CA_PATH
	debugf("CA path: %s\n", CA_PATH);
	if (!SSL_CTX_load_verify_locations(ctx, NULL, CA_PATH)) {
		ERR_print_errors(bio_err);
	}
# else
	if (!SSL_CTX_set_default_verify_paths(ctx)) {
		ERR_print_errors(bio_err);
	}
# endif
#endif
}

/**
Free SSL context. After this function is called, SSL should not be in used.
*/
void free_mossad(void) {
	if (ctx) {
		SSL_CTX_free(ctx);
		ctx = NULL;
	}
}

/** Allocate ssl objects for ssl connection.
*/
int create_ssl(mcrawler_url *u) {
	SSL *ssl = SSL_new(mossad());
	if (!ssl) return -1;
	BIO *sbio = BIO_new_socket(u->sockfd, BIO_NOCLOSE);
	if (!sbio) return -2;
	SSL_set_bio(ssl, sbio, sbio);
	SSL_set_options(ssl, u->ssl_options);
	SSL_set_tlsext_host_name(ssl, u->hostname);
	SSL_set_app_data(ssl, (char *)u);

#ifdef HAVE_SSL_GET0_PARAM
	X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);;
	X509_VERIFY_PARAM_set1_host(vpm, u->hostname, 0);
#endif

	if (u->options & 1<<MCURL_OPT_INSECURE) {
		SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
	} else {
		load_verify_locations();
	}

	u->ssl = ssl;
	return 0;
}

#endif
#endif
