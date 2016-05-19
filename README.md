A Post-Quantum fork of OpenSSL 1.0.2e containing A Practical Ring-LWE Key Exchange Implementation
-------------------------------------------------------------------------------------------------

This software is a fork of OpenSSL 1.0.2e which provides Post-Quantum security using ring-LWE: a practical and efficient Diffie-Hellman-like key exchange which is provably passively secure against quantum and classical adversaries. It is based on the ring learning with errors (ring-LWE) problem and covers a range of security levels and public key sizes.

Two new algorithm identifiers have been defined:

RLWE-RSA-AES128-GCM-SHA256

RLWEP-RSA-AES128-GCM-SHA256

RLWE specifies a power-of-two case ring-LWE key exchange with m=1024 and q=40961, having 256 bits of security and public key size 16384 bits.

RLWEP specifies a prime-case ring-LWE key exchange with m=821 and q=49261, having 256 bits of security and public key size 13120 bits.

Commands
--------

To test a single TLS exchange with one of these new algorithm identifiers:

test/ssltest -d -cert apps/server.pem -cipher RLWE-RSA-AES128-GCM-SHA256

Alternatively run a TLS server and client in separate terminal windows:

To run TLS server:

bin/openssl s_server -debug -cipher RLWE-RSA-AES128-GCM-SHA256:RLWEP-RSA-AES128-GCM-SHA256 -cert apps/server.pem

To run  TLS client:

bin/openssl s_client -debug -cipher RLWE-RSA-AES128-GCM-SHA256:RLWEP-RSA-AES128-GCM-SHA256

TODO
----

Contributions are invited!

This software contains work in progress to complete implementation of a hybrid RLWE/ECDHE key exchange using algorithm identifiers:

RLWE-ECDHE-RSA-AES128-GCM-SHA256

RLWEP-ECDHE-RSA-AES128-GCM-SHA256

and to complete implementation of ECDSA versions using algorithm identifiers:

RLWE-ECDSA-AES128-GCM-SHA256

RLWEP-ECDSA-AES128-GCM-SHA256

RLWE-ECDHE-ECDSA-AES128-GCM-SHA256

RLWEP-ECDHE-ECDSA-AES128-GCM-SHA256

Alternative Security Levels
---------------------------

The RLWE and RLWEP key exchanges have been chosen to map to specific choices of the power-of-two case and prime case respectively. However, a wider range of parameter choices are provided and the code can readily be modified to select one of these. libcrypt provides the following set of parameter choices:

| Algorithm (rlwe_*m*_*q*) | Security   |    Public key size |
| ------------------------ | ---------- | ------------------ |
| rlwe_256_15361           |  80 bits   |    3584 bits       |
| rlwe_512_25601           | 128 bits   |    7680 bits       |
| rlwe_1024_40961          | 256 bits   |   16384 bits       |
| rlwe_337_32353           |  96 bits   |    5040 bits       |
| rlwe_433_35507           | 128 bits   |    6912 bits       |
| rlwe_541_41117           | 160 bits   |    8640 bits       |
| rlwe_631_44171           | 192 bits   |   10080 bits       |
| rlwe_739_47297           | 224 bits   |   11808 bits       |
| rlwe_821_49261           | 256 bits   |   13120 bits       |

To test all these sets, run:

test/ringlwetest

Acknowledgements
----------------

This code is forked from https://github.com/openssl/openssl/tree/OpenSSL_1_0_2e.

The ring-LWE key exchange in this code is adapted from the standalone implementation published at https://github.com/vscrypto/ringlwe. The algorithm for the power-of-two case is described in the paper "A Practical Key Exchange for the Internet using Lattice Cryptography" by Vikram Singh, available at http://eprint.iacr.org/2015/138, and the algorithm for the prime case is described in "Even More Practical Key Exchanges for the Internet using Lattice Cryptography" by Vikram Singh and Arjun Chopra, available at http://eprint.iacr.org/2015/1120. These in turn are a version of the passively secure key exchange described in the paper "Lattice Cryptography for the Internet" by Chris Peikert, available at http://eprint.iacr.org/2014/070.

Substantial parts of this fork are copied from the OpenSSL fork published by Joppe W. Bos, Craig Costello, Michael Naehrig, and Douglas Stebila at https://github.com/dstebila/openssl-rlwekex/tree/OpenSSL_1_0_1-stable, and described in their paper "Post-quantum key exchange for the TLS protocol from the ring learning with errors problem", available at http://eprint.iacr.org/2014/599.
