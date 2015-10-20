ppk
======
[![Travis CI](https://travis-ci.org/davidmoten/ppk.svg)](https://travis-ci.org/davidmoten/ppk)<br/>
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.davidmoten/ppk/badge.svg?style=flat)](https://maven-badges.herokuapp.com/maven-central/com.github.davidmoten/ppk)<br/>


Public/Private Key encryption using Java.

Features
* Builders and method chaining
* byte[] encryption/decryption
* String encryption/decryption

Maven dependency
--------------------
This libray is available on Maven Central.

Add this maven dependency to your pom.xml:

```xml
<dependency>
    <groupId>com.github.davidmoten</groupId>
    <artifactId>ppk</artifactId>
    <version>0.1.2</version>
</dependency>
```


Generate keys
-----------------
We want to generate two files `public.der` and `private.der`:

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

If you are encrypting many things then its more efficient to use a single PPK object:

```java
PPK ppk = PPK.publicKey("/public.der").build();
List<byte[]> encrypted = 
    list.stream()
        .map(ppk::encrypt)
        .collect(Collectors.toList());
```






