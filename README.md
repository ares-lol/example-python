# Example
A Python example for Ares.lol using RSA asymmetrical encryption.

# Encryption
To provide the best security we use asymmetrical encryption with RSA-4096

The client generates a public key/private key pair; then, it encrypts a message containing its public key using the server's public key. The server then decrypts that using its private key and responds with a message encrypted using the client's public key.

![Alice and Bob example](https://bjc.edc.org/March2019/bjc-r/img/3-lists/525px-Public_key_encryption.png)

# Streaming
If you want to stream simply call the `module` function on an authenticated `session_ctx` object.
```
image = session_ctx.module("70da57d7-da83-40e4-909f-4814fd2463ad")

decrypted_image = image.decrypt()

# work with image
```

# Variables
To get a variable simply call the `variable` function on an authenticated `session_ctx` object.
```
session_ctx.variable("var_1")
```

# Ares.lol
Ares.lol is a authentication system with a focus on security and quality.
[Check it out](https://ares.lol)
