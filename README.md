# Oz Haskell Implementation

[![Build Status](https://travis-ci.org/rvl/hsoz.svg?branch=master)](https://travis-ci.org/rvl/hsoz) [![Hackage](https://img.shields.io/hackage/v/hsoz.svg)]()

*hsoz* is a Haskell implementation of the Iron, Hawk, and Oz web
authentication protocols. These protocols originate from the OAuth2
standardisation process, but are designed to be simpler to implement
for the common case of web applications.

## Introduction

In the words of their principal designer:

**Iron** is a cryptographic utility for sealing a JSON object using
symmetric key encryption with message integrity verification. Or in
other words, it lets you encrypt an object, send it around (in
cookies, authentication credentials, etc.), then receive it back and
decrypt it. The algorithm ensures that the message was not tampered
with, and also provides a simple mechanism for password rotation.

**Hawk** is an HTTP authentication scheme using a message
authentication code (MAC) algorithm to provide partial HTTP request
cryptographic verification.

**Oz** is a web authorization protocol based on industry best
practices. Oz combines the Hawk authentication protocol with the
Iron encryption protocol to provide a simple to use and secure
solution for granting and authenticating third-party access to an
API on behalf of a user or an application.

## Documentation

The Haddock documentation is on [Hackage](http://hackage.haskell.org/package/hsoz)
and at https://rodney.id.au/docs/hsoz/.

 * [Network.Iron](http://hackage.haskell.org/package/hsoz/docs/Network-Iron.html)
 * [Network.Hawk](http://hackage.haskell.org/package/hsoz/docs/Network-Hawk.html)
 * [Network.Oz](http://hackage.haskell.org/package/hsoz/docs/Network-Oz.html)

## Example Usage

See the [Network.Iron](http://hackage.haskell.org/package/hsoz/docs/Network-Iron.html)
documentation, and the [example](./example/) directory of this
repository.

## Status

This is an in-progress experiment in implementing the protocol in
Haskell.

 * **Iron**: complete
 * **Hawk**: complete
 * **Oz**: under construction.
 * **Example web application**: under construction.

*Please note*: until the example application is built, this library
cannot be considered "battle-tested".

There is also an `org-mode` file: [todo.org](./todo.org?raw=1).

## Development

I welcome collaborators, particularly anyone who would like to develop
authentication plugins for frameworks such as
[Snap](http://snapframework.com/) and
[Servant](https://haskell-servant.github.io/), or a manager for
[Wreq](http://www.serpentine.com/wreq/).

### Building with Stack

```
stack build
```

### Building with Nix

```
nix-shell -p cabal2nix --command "cabal2nix --shell . > default.nix"
nix-shell --command "cabal configure"
cabal build
```

## Credits

This module is based on the Javascript code and documentation by Eran
Hammer and others. A fair amount of Hammer's descriptive text has been
incorporated into this documentation, as well as the cool logos.
