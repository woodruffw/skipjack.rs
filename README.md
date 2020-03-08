skipjack.rs
===========

[![Build Status](https://img.shields.io/github/workflow/status/woodruffw/skipjack.rs/CI/master)](https://github.com/woodruffw/skipjack.rs/actions?query=workflow%3ACI)

**Note: Skipjack is not suitable for contemporary use. This library exists as an example,
and not for consumption.**

skipjack.rs is a straight-line (meaning no branches or loops) Rust implementation of the
[Skipjack](https://en.wikipedia.org/wiki/Skipjack_(cipher)) cipher,
best known for its use by the NSA in the [Clipper chip](https://en.wikipedia.org/wiki/Clipper_chip).

skipjack.rs has three primary goals (all for educational purposes, for yours truly):

1. To represent safe, idiomatic Rust in a cryptographic context
2. To be easy to read and understand with a minimal understanding of Rust,
even without a background in cryptography
3. To directly reflect the NIST specification for Skipjack (i.e., no optimizations or shortcuts)

## Design

This implementation attempts to adhere closely to the
[NIST-provided specification](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/skipjack/skipjack.pdf)
in design, and does not support any modes of operation other than single-block
[codebook](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_(ECB)).

## Installation

You should not use Skipjack (or skipjack.rs) for anything serious. But, if you'd like to play
with it, you can install it via `cargo`:

```toml
[dependencies]

skipjack = "0.1.0"
```

Documentation is available on [docs.rs](https://docs.rs/crate/skipjack).
