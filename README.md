ppk
======
[![Travis CI](https://travis-ci.org/davidmoten/ppk.svg)](https://travis-ci.org/davidmoten/ppk)<br/>
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.davidmoten/ppk/badge.svg?style=flat)](https://maven-badges.herokuapp.com/maven-central/com.github.davidmoten/ppk)<br/>

Concise Public Private Key encryption using Java.

Features
* Builders and method chaining
* `byte[]` encryption/decryption
* `String` encryption/decryption
* streaming encryption/decryption

Maven dependency
--------------------
This library is available on Maven Central.

Add this maven dependency to your pom.xml:
```xml
<dependency>
    <groupId>com.github.davidmoten</groupId>
    <artifactId>ppk</artifactId>
    <version>0.1.5</version>
</dependency>
```

Implementation details
-----------------------------
This library uses a 2048 bit [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) public key to encrypt a generated (per instance of `PPK`) 128 bit [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) key which is prepended with the AES encrypted message. The RSA algorithm used is `RSA/ECB/OAEPWithSHA1AndMGF1Padding` which uses [Optimal Asymmetric Encryption Padding](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding). This RSA variant has improved strength against [plaintext](https://en.wikipedia.org/wiki/Chosen-plaintext_attack) attack.

Note that RSA can't be used to encrypt a message of arbitrary length because the maximum size of input in our case is 214 bytes. The AES key satisfies this criterion though, that's why it's used here. 256 bit AES is not used in this library because Java needs policy file additions to make it happen and 128 bit AES is currently strong enough. From [Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#Known_attacks):

>As for now, there are no known practical attacks that would allow anyone to read correctly implemented AES [128 bit] encrypted data

The decrypt functionality knows about the format of the encrypted bytes and extracts the AES key using the RSA private key and then decodes the remaining bytes using the extracted AES key.

The output from the encryption method in this library is a byte sequence comprised of:

* 1 byte = length in bytes of RSA encrypted AES key - 1
* the bytes of the RSA encrypted AES key
* the bytes of the AES encrypted message

If you do just want to use RSA on short input (<=214 bytes) you can use `PPK.encryptRSA()` and `PPK.decryptRSA()` methods.

Generate keys
-----------------
You'll need public and private key files. They can be generated using `openssl`:

```bash
openssl genrsa -out keypair.pem 2048
openssl rsa -in keypair.pem -outform DER -pubout -out public.der
openssl pkcs8 -topk8 -nocrypt -in keypair.pem -outform DER -out private.der
```
Now move `public.der` and `private.der` somewhere so you can access them with your code.

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
The examples above assume `/private.der` and `/public.der` are on the classpath. You can use overloads for `File` definitions or pass in `byte[]` of `InputStream` values for those keys.

Encrypt a string:
```java
String content = "Hello World";
byte[] encrypted = 
    PPK.publicKey(new File("/home/me/.keys/public.der"))
       .encrypt(content, Charsets.UTF_8);
```
If you are encrypting many things then its more efficient to use a single PPK object:
```java
PPK ppk = PPK.publicKey("/public.der").build();
List<byte[]> encrypted = 
    list.stream()
        .map(ppk::encrypt)
        .collect(Collectors.toList());
```
Round trip example:
```java
PPK ppk = PPK.publicKey("/public.der")
             .privateKey("/private.der")
             .build();
//result should be the same as bytes
byte[] result = ppk.decrypt(ppk.encrypt(bytes));
```
You can also minimize your memory usage by using the `encrypt` and `decrypt` methods with `InputStream` and `OutputStream` parameters:
```java
PPK.publicKey("/public.der")
   .encrypt(inputStream, outputStream);
```
```java
PPK.privateKey("/private.der")
   .decrypt(inputStream, outputStream);
```

Base64
---------------
A common use case is to encrypt a text password and store it encrypted encoded in [Base64](https://en.wikipedia.org/wiki/Base64). *ppk* has convenience methods to support this:

```java
String base64 = 
    PPK.publicKey("/public.der")
       .encryptAsBase64("mypassword");
```

To decrypt the Base64 string as a string:
```java
String password = 
    PPK.privateKey("/private.der")
       .decryptBase64(base64);
```

Thread safety
---------------

Please note that `PPK` is not thread safe! Create a new one for each thread or use a pool.



