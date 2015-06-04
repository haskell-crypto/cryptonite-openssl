cryptonite-openssl
==================

[![Build Status](https://travis-ci.org/vincenthz/cryptonite-openssl.png?branch=master)](https://travis-ci.org/vincenthz/cryptonite-openssl)
[![BSD](http://b.repl.ca/v1/license-BSD-blue.png)](http://en.wikipedia.org/wiki/BSD_licenses)
[![Haskell](http://b.repl.ca/v1/language-haskell-lightgrey.png)](http://haskell.org)

Support for OpenSSL based crypto operations in Haskell, as a bolt-in to [cryptonite](http://hackage.haskell.org/package/cryptonite)

If you have no idea what're you doing, please do not use this directly, rely on
higher level protocols or higher level implementation.

Documentation: [cryptonite-openssl on hackage](http://hackage.haskell.org/package/cryptonite-openssl)

Support
-------

cryptonite-openssl supports the following platform:

* Windows >= 8
* OSX >= 10.8
* Linux

On the following architectures:

* x86-64
* i386

On the following haskell versions:

* GHC 7.0.x
* GHC 7.4.x
* GHC 7.6.x
* GHC 7.8.x
* GHC 7.10.x

Further platforms and architectures probably works too, but until maintainer(s) don't have regular
access to them, we can't commit for further support

Building on MacOS X
-------------------

* using openssl system library
* using alternative installation

Building on windows
-------------------

