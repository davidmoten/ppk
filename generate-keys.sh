#!/bin/bash
# set -x
set -e
mkdir -p target
openssl genrsa -out target/keypair.pem 2048
openssl rsa -in target/keypair.pem -outform DER -pubout -out target/public.der
openssl pkcs8 -topk8 -nocrypt -in target/keypair.pem -outform DER -out target/private.der
rm target/keypair.pem
echo "created public.der and private.der in target directory"
