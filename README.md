# php-ed25519-ext
PHP extension wrapping ed25519, an Elliptic Curve Digital Signature Algortithm, developed by Dan Bernstein, Niels Duif, Tanja Lange, Peter Schwabe, and Bo-Yin Yang.

This extensions is based on two projects: ed25519 implemention from https://github.com/floodyberry/ed25519-donna and
original PHP curve25519 extension from https://github.com/lt/php-curve25519-ext
 
### How to install:

```
git clone git://github.com/encedo/php-ed25519-ext.git
cd php-ed25519-ext
phpize
./configure
make
sudo make install
```
Finally add `extension=ed25519.so` to your /etc/php.ini

### Building a Debian package

You can build it as a Debian package using

```
git clone git://github.com/encedo/php-ed25519-ext.git
cd php-ed25519-ext
sudo apt-get install php5-dev dh-php5
fakeroot debian/rules binary
```

### Usage:

Generate 32 secret random bytes from a cryptographically safe source e.g.

```
// PHP 7
$mySecret = random_bytes(32);

// <= PHP 5.6
$mySecret = openssl_random_pseudo_bytes(32);

```

Then generate the corresponding 32-byte public key by calling

```
$myPublic = ed25519_publickey($mySecret);
```

To sign a ```$message``` simply call

```
$signature = ed25519_sign($message, $mySecret, $myPublic);
```

To verify the ```$signature``` for a given ```$message``` against ```$myPublic``` call

```
$status = ed25519_sign_open($message,  $myPublic, $signature);
```

If ```$status === TRUE``` the ```$signature``` is just fine :)


### Example ```test.php```:
```
<?php

$mySecret = openssl_random_pseudo_bytes(32);
$myPublic = ed25519_publickey($mySecret);

$message = 'Hello, World!';

$signature = ed25519_sign($message, $mySecret, $myPublic);
var_dump( ed25519_sign_open($message,  $myPublic, $signature) );

?>


