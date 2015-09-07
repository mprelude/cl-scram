# cl-scram

**THIS LIBRARY IS NOT IN A WORKING STATE.
PLEASE DO NOT DOWNLOAD IT AND EXPECT IT TO WORK IN YOUR CODE.**

[TOC]

## Introduction

I started developing this library when I was trying to use MongoDB with the [cl-mongo](https://github.com/fons/cl-mongo) driver, and it became apparent that the driver had not been updated to use mongo's modern SCRAM-SHA1 authentication method.

Given the choices of relying on an antiquated MD5-based login method or writing a shiny new library, I chose the latter. The purpose of `cl-scram` is to allow for everything the client needs to do SCRAM login with the SHA1 hash algorithm.

The library is dependent on `ironclad` for all cryptographic functions. It does not rely on any DIY crypto.

## License

The project is licensed under the Revised BSD License.

```
Copyright (c) 2015, Matt Prelude
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of Matt Prelude nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL MATT PRELUDE BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Installation

Use ASDF to install `cl-scram` as it has a number of dependencies. I will be looking to include `cl-scram` in Quicklisp later on.

```
* (asdf:load-system :cl-scram)
```

All of the functions are in the `#:cl-scram` package.

## Testing

## Usage

### Generating a client nonce

The first step in a SCRAM request is to generate a nonce for the request. This can be done as follows:

```
* (gen-client-nonce)

"x6uHptrIM6PAFMtmbGCN8uuy0LSnZCww"
```

This is fully supported by `cl-scram`s message-generating functions, which accept a `:nonce` parameter.

### Generating first client message

Next, we need to generate the first client message. To generate an un-encoded message, you can call the `gen-client-initial-message` function with the username & nonce:

```
* (gen-client-initial-message :username "username" :nonce "x6uHptrIM6PAFMtmbGCN8uuy0LSnZCww")

"n,,n=username,r=x6uHptrIM6PAFMtmbGCN8uuy0LSnZCww"
```

You'll typically want this base64 encoded. To do this, you can either wrap the call in `base64-encode` or call the convenience function `gen-client-encoded-initial-message`:

```
* (base64-encode (gen-client-initial-message :username "username" :nonce "x6uHptrIM6PAFMtmbGCN8uuy0LSnZCww"))

"biwsbj11c2VybmFtZSxyPXg2dUhwdHJJTTZQQUZNdG1iR0NOOHV1eTBMU25aQ3d3"
* (gen-client-encoded-initial-message :username "username" :nonce "x6uHptrIM6PAFMtmbGCN8uuy0LSnZCww")

"biwsbj11c2VybmFtZSxyPXg2dUhwdHJJTTZQQUZNdG1iR0NOOHV1eTBMU25aQ3d3"
```


You'll need to pass this to the server.

### Generating final client message

The server should respond with a base64-encoded string, which when decoded looks something like this:

```
r=6d442b5d9e51a740f369e3dcecf3178ec12b3985bbd4a8e6f814b422ab766573,s=Vdptv0j/N6fs2qtVADc1Xg==,i=8192
```

In order to generate the final response, we'll need to create a new request:

TODO: ADD client request generation docs.

### Understanding the first server response

The server should respond with a base64-encoded string, when decoded, this will have three parameters:

```
r=6d442b5d9e51a740f369e3dcecf3178ec12b3985bbd4a8e6f814b422ab766573,s=Vdptv0j/N6fs2qtVADc1Xg==,i=8192
```

- The value of `r` is the nonce.
- The value of `s` is the salt (base64-encoded).
- The value of `i` is the number of iterations.

`cl-scram` provides three convenience methods to access & validate the data.

To get the nonce (and confirm that it correctly starts with the client nonce), call `parse-server-nonce` passing the decoded message response & the client nonce:

```
* (parse-server-nonce :nonce "6d44" :response "r=6d442b5d9e51a740f369e3dcecf3178ec12b3985bbd4a8e6f814b422ab766573,s=Vdptv0j/N6fs2qtVADc1Xg==,i=8192")

"6d442b5d9e51a740f369e3dcecf3178ec12b3985bbd4a8e6f814b422ab766573"
```

And to get the salt (base64-decoded), call `parse-server-salt`:

```
* (parse-server-salt :response "r=6d442b5d9e51a740f369e3dcecf3178ec12b3985bbd4a8e6f814b422ab766573,s=Vdptv0j/N6fs2qtVADc1Xg==,i=8192")

"UÚm¿Hÿ7§ìÚ«U75^"
```

And finally, to get the number of iterations, you can call `parse-server-iterations`:

```
* (parse-server-iterations :response "r=6d442b5d9e51a740f369e3dcecf3178ec12b3985bbd4a8e6f814b422ab766573,s=Vdptv0j/N6fs2qtVADc1Xg==,i=8192")

"8192"
```

### Dealing with final server message

## Donations

If this library has been helpful to you, I don't seek any donations, but please feel free to [donate to Quicklisp](https://www.quicklisp.org/donations.html), one of the most important projects in the CL ecosystem.

## TODO

1. Implement [SASLprep](https://www.ietf.org/rfc/rfc4013.txt) algorithm to support the full gamut of passwords. For now, using the library with passwords containing unsupported characters is considered unsupported behavior.