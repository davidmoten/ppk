#!/bin/bash
set -x
set -e
openssl genrsa -out keypair.pem 2048
openssl rsa -in keypair.pem -outform DER -pubout -out public.der
openssl pkcs8 -topk8 -nocrypt -in keypair.pem -outform DER -out private.der
rm keypair.pem
