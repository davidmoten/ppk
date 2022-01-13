ppk
======
<a href="https://github.com/davidmoten/ppk/actions/workflows/ci.yml"><img src="https://github.com/davidmoten/ppk/actions/workflows/ci.yml/badge.svg"/></a><br/>
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.davidmoten/ppk/badge.svg?style=flat)](https://maven-badges.herokuapp.com/maven-central/com.github.davidmoten/ppk)<br/>

Concise Public Private Key encryption using Java.

Features
* Builders and method chaining
* `byte[]` encryption/decryption
* `String` encryption/decryption
* streaming encryption/decryption

Maven [site](http://davidmoten.github.io/ppk/) including [javadoc](http://davidmoten.github.io/ppk/apidocs/index.html).

Maven dependency
--------------------
This library is available on Maven Central.

Add this maven dependency to your pom.xml:
```xml
<dependency>
    <groupId>com.github.davidmoten</groupId>
    <artifactId>ppk</artifactId>
    <version>VERSION_HERE</version>
</dependency>
```

Generating keys
-----------------
You'll need public and private key files. They can be generated using `openssl`, java, or a maven plugin:

### Generating keys with OpenSSL

```bash
openssl genrsa -out keypair.pem 2048
openssl rsa -in keypair.pem -outform DER -pubout -out public.der
openssl pkcs8 -topk8 -nocrypt -in keypair.pem -outform DER -out private.der
```
Now move `public.der` and `private.der` somewhere so you can access them with your code (you can delete `keypair.pem`).

You can instead use the provided bash script `generate-keys.sh`:

```bash
./generate-keys.sh
```

which writes `public.der` and `private.der` to the current directory.

### Generating keys with Java

```java
KeyPair kp = PPK.createKeyPair();
byte[] privateKey = kp.privateKeyDer();
byte[] publicKey = kp.publicKeyDer();
//you might write those byte arrays to files to get 
// private.der and public.der
...
```

### Generating keys with ppk-maven-plugin
```xml
<plugin>
    <groupId>com.github.davidmoten</groupId>
    <artifactId>ppk-maven-plugin</artifactId>
    <version>VERSION_HERE</version>
    <executions>
        <execution>
            <goals>
                <goal>create</goal>
            </goals>
            <configuration>
                <privateKeyFile>${project.build.directory}/private.der</privateKeyFile>
                <publicKeyFile>${project.build.directory}/public.der</publicKeyFile>
            </configuration>
        </execution>
    </executions>
</plugin>
```

To call:

```bash
mvn ppk:create
```


Encrypting and decrypting
-------------------------
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
If you are encrypting many things then its more efficient to use a single PPK object (though the AES secret key will be the same for all encryptions unless you call `.unique()` in the builder):
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
A common use case is to encrypt a text password and store it encoded in [Base64](https://en.wikipedia.org/wiki/Base64) (in a configuration file for example). *ppk* has convenience methods to support this:

```java
String base64 = 
    PPK.publicKey("/public.der")
       .encryptAsBase64("mypassword");
System.out.println(base64);
```

which produces this output (364 characters):
```
/66kjqBF6C99vHTQmE2yk4HRD+3c9cNlCg3PO8fW4w7GvZokV0P7CUnWzI2SQuD7sOnEeAjMWfQZePpNk2cEVNMyKJUt2Gs3N92sgXjJra0fb7qqmQhWBWAKv/3avKO5SE3WcHT1E053tgs7lqiMoZEyZBdvqUY645UPnfQETMsBcXt+1fdo8udhdN+BibCJSJWZi50LziEBMllAJssY6DP8XFtZad7iknee32g+waS71ALT3DE/QaJhByeakKXjUhZKlH3zYMcNjF9/kuv1ORAgNriIS3mb7QDXwuvdFkAA3/7x3FE6fdYz2htsPNiEpHI8sYLRlbAsbZO2BrvKV6l7kl0W96bFG4BOoKaZIhR8
```

To decrypt:
```java
String password = 
    PPK.privateKey("/private.der")
       .decryptBase64(base64);
```

Thread safety
---------------

Please note that `PPK` is not thread safe! Create a new one for each thread or use a pool.


Implementation details
-----------------------------
This library uses a 2048 bit [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) public key to encrypt a generated (per instance of `PPK`) 128 bit [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) key which is prepended to the AES encrypted message. The RSA algorithm used is `RSA/ECB/OAEPWithSHA1AndMGF1Padding` which uses [Optimal Asymmetric Encryption Padding](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding). This RSA variant has improved strength against [plaintext](https://en.wikipedia.org/wiki/Chosen-plaintext_attack) attack.

Note that RSA can't be used to encrypt a message of arbitrary length because the maximum size of input in our case is 214 bytes. The AES key satisfies this criterion though, that's why it's used here. 256 bit AES is not used in this library because Java needs policy file additions to make it happen and 128 bit AES is currently strong enough. From [Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#Known_attacks):

>At present, there is no known practical attack that would allow someone without knowledge of the key to read data encrypted by AES [128 bit] when correctly implemented.

The decrypt functionality knows about the format of the encrypted bytes and extracts the AES key using the RSA private key and then decodes the remaining bytes using the extracted AES key.

The output from the encryption method in this library is a byte sequence comprised of:

* 1 byte = length in bytes of RSA encrypted AES key - 1
* the bytes of the RSA encrypted AES key
* the bytes of the AES encrypted message

<img src="ppk/src/docs/format.png?raw=true" /> 

If you do just want to use RSA on short input (<=214 bytes) you can use `PPK.encryptRSA()` and `PPK.decryptRSA()` methods.


