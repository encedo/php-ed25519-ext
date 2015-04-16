#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ed25519.h"

PHP_FUNCTION(ed25519_publickey)
{
	unsigned char *secret;
	int secret_len;

  ed25519_public_key pk;
  //ed25519_secret_key sk
  
  
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &secret, &secret_len) == FAILURE) {
		RETURN_FALSE;
	}

	if (secret_len != 32) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Private key must be 32 bytes");
		RETURN_FALSE;
	}

  //memmove(sk, secret, 32);
	//ed25519_publickey(sk, pk);
	ed25519_publickey(secret, pk);

	RETURN_STRINGL(pk, 32, 1);
}

PHP_FUNCTION(ed25519_sign_open)
{
	unsigned char *m;
	int m_len;
	
	unsigned char *pk;
	int pk_len;

	unsigned char *rs;
	int rs_len;
	
	ed25519_public_key PK;
	ed25519_signature RS
	
	int result;


	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &m, &m_len, &pk, &pk_len, &rs, &rs_len) == FAILURE) {
		RETURN_FALSE;
	}

	if (pk_len != 32) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Public key must be 32 bytes");
		RETURN_FALSE;
	}

	if (rs_len != 64) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Signature must be 64 bytes");
		RETURN_FALSE;
	}

  //memmove(sk, secret, 32);
  //memmove(sk, secret, 32);

  result = ed25519_sign_open(m, m_len, pk, rs);
  if (result)
    RETURN_TRUE;
  else
    RETURN_FALSE;	
}

PHP_FUNCTION(ed25519_sign)
{
	unsigned char *m;
	int m_len;
	
	unsigned char *pk;
	int pk_len;

	unsigned char *sk;
	int sk_len;
	
	ed25519_public_key PK;
	ed25519_signature RS
	
	int result;


	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &m, &m_len, &sk, &sk_len, &pk, &pk_len) == FAILURE) {
		RETURN_FALSE;
	}

	if (pk_len != 32) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Public key must be 32 bytes");
		RETURN_FALSE;
	}

	if (sk_len != 32) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Private key must be 32 bytes");
		RETURN_FALSE;
	}

  //memmove(sk, secret, 32);
  //memmove(sk, secret, 32);

  ed25519_sign(m, m_len, sk, pk, RS);
  
  RETURN_STRINGL(RS, 54, 1);
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


const zend_function_entry ed25519_functions[] = {
	PHP_FE(ed25519_publickey, arginfo_ed25519_publickey)
	PHP_FE(ed25519_sign_open, arginfo_ed25519_sign_open)
	PHP_FE(ed25519_sign, arginfo_ed25519_sign)
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
