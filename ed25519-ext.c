#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ed25519.h"
#include "ed25519-ext.h"
#include "ext/standard/info.h"
#include "zend_exceptions.h"
#include "ext/spl/spl_exceptions.h"

PHP_FUNCTION(ed25519_publickey)
{
	char *secret;

#if PHP_VERSION_ID >= 70000
    size_t secret_len;
#else
    int secret_len;
#endif  

    ed25519_public_key pk;
  
#ifndef FAST_ZPP
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &secret, &secret_len) == FAILURE) {
        RETURN_FALSE;
    }
#else
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(secret, secret_len)
    ZEND_PARSE_PARAMETERS_END();
#endif

	if (secret_len != 32) {
        zend_throw_exception(spl_ce_InvalidArgumentException, "Secret must be 32 bytes", 0 TSRMLS_CC);
    }

	ed25519_publickey(secret, pk);

#if PHP_VERSION_ID >= 70000
    RETURN_STRINGL(pk, 32);
#else
    RETURN_STRINGL(pk, 32, 1);
#endif
}

PHP_FUNCTION(ed25519_sign_open)
{
	char *m;
	char *pk;
	char *rs;

#if PHP_VERSION_ID >= 70000
    size_t m_len;
    size_t pk_len;
    size_t rs_len;
#else
    int m_len;
    int pk_len;
    int rs_len;
#endif  

	int result;

#ifndef FAST_ZPP
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &m, &m_len, &pk, &pk_len, &rs, &rs_len) == FAILURE) {
        RETURN_FALSE;
    }
#else
    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_STRING(m, m_len)
        Z_PARAM_STRING(pk, pk_len)
        Z_PARAM_STRING(rs, rs_len)
    ZEND_PARSE_PARAMETERS_END();
#endif

    if (pk_len != 32) {
        zend_throw_exception(spl_ce_InvalidArgumentException, "Public key must be 32 bytes", 0 TSRMLS_CC);
    }

    if (rs_len != 64) {
        zend_throw_exception(spl_ce_InvalidArgumentException, "Signature must be 64 bytes", 0 TSRMLS_CC);
    }

  	result = ed25519_sign_open(m, m_len, pk, rs);
 	if (result == 0) {
		RETURN_TRUE;
  	} else {
		RETURN_FALSE;	
  	}
}

PHP_FUNCTION(ed25519_sign)
{
	char *m;
	char *pk;
	char *sk;

#if PHP_VERSION_ID >= 70000
    size_t m_len;
    size_t pk_len;
    size_t sk_len;
#else
    int m_len;
    int pk_len;
    int sk_len;
#endif  

	ed25519_signature RS;

#ifndef FAST_ZPP
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &m, &m_len, &sk, &sk_len, &pk, &pk_len) == FAILURE) {
        RETURN_FALSE;
    }
#else
    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_STRING(m, m_len)
        Z_PARAM_STRING(sk, sk_len)
        Z_PARAM_STRING(pk, pk_len)
    ZEND_PARSE_PARAMETERS_END();
#endif

    if (sk_len != 32) {
        zend_throw_exception(spl_ce_InvalidArgumentException, "Secret must be 32 bytes", 0 TSRMLS_CC);
    }

    if (pk_len != 32) {
        zend_throw_exception(spl_ce_InvalidArgumentException, "Public key must be 32 bytes", 0 TSRMLS_CC);
    }

  	ed25519_sign(m, m_len, sk, pk, RS);
  
#if PHP_VERSION_ID >= 70000
    RETURN_STRINGL(RS, 64);
#else
    RETURN_STRINGL(RS, 64, 1);
#endif
}

PHP_FUNCTION(curved25519_scalarmult_basepoint)
{
    char *secret;

#if PHP_VERSION_ID >= 70000
    size_t secret_len;
#else
    int secret_len;
#endif  

    curved25519_key pk;

#ifndef FAST_ZPP
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &secret, &secret_len) == FAILURE) {
        RETURN_FALSE;
    }
#else
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(secret, secret_len)
    ZEND_PARSE_PARAMETERS_END();
#endif

    if (secret_len != 32) {
        zend_throw_exception(spl_ce_InvalidArgumentException, "Secret must be 32 bytes", 0 TSRMLS_CC);
    }

    curved25519_scalarmult_basepoint(pk, secret);

#if PHP_VERSION_ID >= 70000
    RETURN_STRINGL(pk, 32);
#else
    RETURN_STRINGL(pk, 32, 1);
#endif
}


ZEND_BEGIN_ARG_INFO_EX(arginfo_ed25519_publickey, 0, 0, 1)
	ZEND_ARG_INFO(0, secret)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ed25519_sign_open, 0, 0, 3)
	ZEND_ARG_INFO(0, message)
	ZEND_ARG_INFO(0, public)
	ZEND_ARG_INFO(0, signature)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ed25519_sign, 0, 0, 3)
	ZEND_ARG_INFO(0, message)
	ZEND_ARG_INFO(0, secret)
	ZEND_ARG_INFO(0, public)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_curved25519_scalarmult_basepoint, 0, 0, 1)
    ZEND_ARG_INFO(0, secret)
ZEND_END_ARG_INFO()


const zend_function_entry ed25519_functions[] = {
	PHP_FE(ed25519_publickey, arginfo_ed25519_publickey)
	PHP_FE(ed25519_sign_open, arginfo_ed25519_sign_open)
	PHP_FE(ed25519_sign, arginfo_ed25519_sign)
	PHP_FE(curved25519_scalarmult_basepoint, arginfo_curved25519_scalarmult_basepoint)
	PHP_FE_END
};

PHP_MINFO_FUNCTION(ed25519)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "ed25519 support", "enabled");
	php_info_print_table_end();
}

zend_module_entry ed25519_module_entry = {
	STANDARD_MODULE_HEADER,
	"ed25519",
	ed25519_functions,
	NULL,
	NULL,
	NULL,
	NULL,
	PHP_MINFO(ed25519),
	NO_VERSION_YET,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_ED25519
ZEND_GET_MODULE(ed25519)
#endif
