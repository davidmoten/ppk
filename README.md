ppk
======
[![Travis CI](https://travis-ci.org/davidmoten/ppk.svg)](https://travis-ci.org/davidmoten/ppk)<br/>
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.davidmoten/ppk/badge.svg?style=flat)](https://maven-badges.herokuapp.com/maven-central/com.github.davidmoten/ppk)<br/>

Concise Public/Private Key encryption using Java.

Features
* Builders and method chaining
* `byte[]` encryption/decryption
* `String` encryption/decryption

Maven dependency
--------------------
This library is available on Maven Central.

Add this maven dependency to your pom.xml:

```xml
<dependency>
    <groupId>com.github.davidmoten</groupId>
    <artifactId>ppk</artifactId>
    <version>0.1.3</version>
</dependency>
```

Implementation details
-----------------------------
This library uses a 2048 bit RSA public key to encrypt a generated (per instance of PPK) 128 bit AES key which is prepended with the AES encrypted message.

Note that RSA can't be used to encrypt a message of arbitrary length because the maximum size of input is 245 bytes. The AES key satisfies this criterion though, that's why its in use. 256 bit AES is not used in this library because Java needs policy file additions to make it happen and 128 bit AES is currently strong enough for most stuff.

The decrypt functionality knows about the format of the encrypted bytes and extracts the AES key using the RSA private key and then decodes the remaining bytes using the extracted AES key.

The output from the encryption method in this library is a byte sequence comprised of:

* 1 byte = length in bytes of RSA encrypted AES key
* the bytes of the RSA encrypted AES key
* the bytes of the AES encrypted message

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



