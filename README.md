# Ephemeral Diffie-Hellman Over COSE
[![CMake](https://github.com/openwsn-berkeley/EDHOC-C/actions/workflows/cmake.yml/badge.svg?branch=master)](https://github.com/openwsn-berkeley/EDHOC-C/actions/workflows/cmake.yml)
[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
## Introduction

This repository contains a C implementation of the LAKE IETF candidate EDHOC (Ephemeral Diffie-Hellman Over COSE). EDHOC is a  compact and lightweight authenticated Diffie-Hellman key exchange with ephemeral keys. It provides mutual authentication perfect forward secrecy, and identity protection. EDHOC is intended for usage in constrained scenarios and a main use case is to establish an OSCORE security context. By reusing COSE for cryptography, CBOR for encoding, and CoAP for transport, the additional code size can be kept very low.

The full specification can be found [here](https://datatracker.ietf.org/doc/draft-ietf-lake-edhoc/).

## Overview
EDHOC-C is written in a modular way. It can support different backends for the cryptographic operations and the CBOR encoding routines. Currently [wolfSSL](https://www.wolfssl.com/) and [HACL*](https://hacl-star.github.io/) are supported as backend for the cryptography.  CBOR encoding is provided by [NanoCBOR](https://github.com/bergzand/NanoCBOR).

| ![EDHOC code structure](https://github.com/openwsn-berkeley/EDHOC-C/blob/master/images/edhoc.png?raw=true) |
| :----------------------------------------------------------: |
|                                                              |

## Building EDHOC-C

### Requirements
To build `EDHOC-C` and its backends you'll need:

* CMake
* make
* autoconf
* GCC

### Build

Clone the project:

```bash
$ git clone https://github.com/openwsn-berkeley/EDHOC-C.git
```

Move to the root of the repository and create a `build` folder:

```bash
$ mkdir build && cd build
```

Configure and build:

```bash
$ cmake ..
$ cmake --build .
```

By default EDHOC-C uses wolfSSL as its cryptographic backend. If you wish to use HACL as backend you must update the configure step and rebuild the project:

```bash
$ cmake .. -DEDHOC_CRYTPO_BACKEND=HACL
$ cmake --build .
```

## Contact

Timothy Claeys: <timothy.claeys@inria.fr>





