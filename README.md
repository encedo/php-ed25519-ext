# php-ed25519-ext
PHP extension wrapping ed25519, an Elliptic Curve Digital Signature Algortithm, developed by Dan Bernstein, Niels Duif, Tanja Lange, Peter Schwabe, and Bo-Yin Yang.

This extensions is based on two projects:
1. ed25519 implemention from https://github.com/floodyberry/ed25519-donna
2. original PHP curve25519 extension from https://github.com/lt/php-curve25519-ext
 
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
