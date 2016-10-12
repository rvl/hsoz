# Oz Haskell Implementation

[![Build Status](https://travis-ci.org/rvl/hsoz.svg?branch=master)](https://travis-ci.org/rvl/hsoz)

Oz is a web authentication protocol like OAuth.

> [Iron](https://github.com/hueniverse/iron) is a simple way to take a
> JavaScript object and turn it into a verifiable encoded
> blob. [Hawk](https://github.com/hueniverse/hawk) is a client-server
> authentication protocol providing a rich set of features for a wide
> range of security needs. [Oz](https://github.com/hueniverse/oz)
> combines Iron and Hawk into an authorization solution. Together
> these three modules provide a comprehensive and powerful solution.

This is an in-progress experiment in implementing the protocol in
Haskell.

Full documentation for what is implemented so far is available at:
https://rodney.id.au/docs/hsoz/


## Building with Stack

```
stack build
```

## Building with Nix

```
nix-shell -p cabal2nix --command "cabal2nix --shell . > default.nix"
nix-shell --command "cabal configure"
cabal build
```
