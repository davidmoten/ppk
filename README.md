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
byte[] encrypted = 
    PPK.publicKey("/public.der")
       .encrypt(content, Charsets.UTF_8);
```
Decrypt a string:

```java
String content = 
    PPK.privateKey("/private.der")
       .decrypt(bytes, Charsets.UTF_8);
```

Encrypt bytes:
```java
byte[] encrypted = 
    PPK.publicKey("/public.der")
       .encrypt(bytes);
```

Decrypt bytes:
```java
byte[] decrypted = 
    PPK.privateKey("/private.der")
       .decrypt(bytes);
```


The examples above assume `/private.der` and `/public.der` are on the classpath. You can use overloads for `File` definitions or pass in the `byte[]` values for those keys.

Encrypt a string:

```java
String content = "Hello World";
byte[] encrypted = 
    PPK.publicKey(new File("/home/me/.keys/public.der"))
       .encrypt(content, Charsets.UTF_8);
```






