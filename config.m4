PHP_ARG_ENABLE(ed25519, Whether to enable the "ed25519" extension,
	[  --enable-ed25519       Enable "php-ed25519-ext" extension support])

if test $PHP_ED25519 != "no"; then
	PHP_NEW_EXTENSION(ed25519, ed25519-ext.c ed25519.c, $ext_shared)
fi
