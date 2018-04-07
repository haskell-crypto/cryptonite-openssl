cryptonite-openssl
==================

[![Build Status](https://travis-ci.org/haskell-crypto/cryptonite-openssl.png?branch=master)](https://travis-ci.org/vincenthz/cryptonite-openssl)
[![BSD](http://b.repl.ca/v1/license-BSD-blue.png)](http://en.wikipedia.org/wiki/BSD_licenses)
[![Haskell](http://b.repl.ca/v1/language-haskell-lightgrey.png)](http://haskell.org)

Support for OpenSSL based crypto operations in Haskell, as a bolt-in to [cryptonite](http://hackage.haskell.org/package/cryptonite)

If you have no idea what're you doing, please do not use this directly, rely on
higher level protocols or higher level implementation.

Documentation: [cryptonite-openssl on hackage](http://hackage.haskell.org/package/cryptonite-openssl)

Support
-------

See [Haskell packages guidelines section support](https://github.com/vincenthz/haskell-pkg-guidelines/blob/master/README.md#support)

Building on MacOS X
-------------------

* using openssl system library
* using alternative installation

Building on windows
-------------------

You need the C++ runtime :

* http://www.microsoft.com/downloads/details.aspx?familyid=bd2a6171-e2d6-4230-b809-9a8d7548c1b6

And the right installation of OpenSSL. Some binary installations are available here:

* https://slproweb.com/products/Win32OpenSSL.html

Building with alternative OpenSSL - BoringSSL, LibreSSL
-------------------------------------------------------

Not currently tried or implemented, but this is probably easy to do.
