ppk
======
Public/Private Key encryption using Java.

Generate keys
-----------------

```bash
openssl genrsa -out keypair.pem 2048
openssl rsa -in keypair.pem -outform DER -pubout -out public.der
openssl pkcs8 -topk8 -nocrypt -in keypair.pem -outform DER -out private.der
```

Examples
---------------
Encrypt a string:

```java
String content = "Hello World";
byte[] encrypted = PPK
    .publicKey("/public.der")
    .encrypt(content, Charsets.UTF_8);
```
Decrypt a string:

```java
PPK ppk = PPK.privateKey("/private.der").build();
String content = ppk.decrypt(encrypted, Charsets.UTF_8); 
```

Encrypt bytes:
```java

```




