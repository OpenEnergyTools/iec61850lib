In general, this already looks quite good. Some design choices are just rather uncommon in Rust but common for people new to the language. I noted some of those in the code.

# Things I really like

  * Lots of documentation in the code
  * Lots of unit tests, which also document what they do

# General

  * I noticed you are reimplementing a lot of ASN.1 BER instead of using a library. I guess this is mostly to allow you to learn the language and understand the whole stack. This is fine! In production, I would later switch to an ASN.1 crate like [`rasn`](https://docs.rs/rasn/latest/rasn).
  * Run `cargo clippy` to get hints and suggestions (lints) on your code.
  * Place tests close to the code they are testing. This way, you can also test functions that are not exposed in your interface.
      * See https://doc.rust-lang.org/book/ch11-03-test-organization.html
  * Only mark functions as `pub` if you want your users to use them (e.g., I would not make `encode_float` `pub`).
  * You could also add documentation and examples to your `mod`s and crate. These can also include examples, which will be run by `cargo test` automatically.
      * See here for the tests: https://doc.rust-lang.org/rustdoc/write-documentation/documentation-tests.html
      * To add a comment for the current "thing" (like mod or crate), just use `//!` instead of `///`.

# Error Handling

  * Use `String` instead of `[char; 128]`. `String`s are UTF-8 encoded, while a `char` always takes up four bytes.
  * Consider using an `enum` to list all the possible error conditions. For example:
    ```rust
    pub enum DecodeError {
        /// A boolean value was encoded with more than one byte length
        InvalidBool { position: usize },
    }
    ```
  * I think this blog article might give an overview of the current common practice to package errors: https://momori.dev/posts/rust-error-handling-thiserror-anyhow/

# Check-then-use vs. Option-APIs

In your code, you often perform a check and then access a value. However, there are usually methods available that do both check and access at once, returning an `Option` or `Result` on failure.

```rust
// Instead of this
if slice.len() < idx {
    return Err(OutOfBounds)
}
let element = slive[idx];

// Do this if you return an Option
let element = slice.get(idx)?;

// Or this if you return a Result
let element = slice.get(idx).ok_or(OutOfBounds)?;

// this can also take a range
let element = slice.get(0..idx)...
```

This pattern makes sure that you cannot forget the check when code is moving around.

# Decoder design

## Basic decoding

I would redesign the API to make it harder to misuse. Instead of this API to parse a type:

```rust
pub fn decode_octet_string(
    val: &mut [u8],
    buffer: &[u8],
    buffer_index: usize,
    length: usize,
) -> Result<usize, DecodeError> { ... }
```

Use this:

```rust
fn decode_octet_string(data: &[u8]) -> Result<Vec<u8>, DecodeError> {
    Ok(Vec::from(data))
}
```

So we just pass in the bytes of the element we are decoding at the moment. This makes it relatively simple for the caller; they know about the position and the length. And it makes decoding much simpler since we can never accidentally go out of bounds of the element we are right now decoding.

Also, returning the value only if we successfully parsed it makes sure that the caller can never use an uninitialized value by accident.

## GOOSE decoding

It looks like you are just assuming the order of the fields in the packet. This will work fine in most cases but is quite brittle. If the packet contains errors, you might just parse the wrong data. I would use your `decode_iec_data_element` function here instead and check that the type of the field actually matches what you expected.

# Encoder design

The encoder looks much more like what I would suggest. Did you write this after the decoder? You are already applying a lot more Rust idioms – great\!

The only thing I can really complain about here is that I would pass the `buffer: &mut [u8]` starting from the place you want to write to. This way, you can leave out the `buffer_index`.

# Advanced topics

## Fuzz testing

In general, when parsing protocols, it is advisable to add fuzz testing. This runs your tests with random inputs to see if it crashes with any of them. It is intelligent in how to mutate the input so it covers as much of your code as possible.

Adding it to a Rust project is relatively simple: https://rust-fuzz.github.io/book/introduction.html

## Borrowing

In the decoder, you could reference the input instead of copying out the data like so:

```rust
fn decode_octet_string(data: &[u8]) -> Result<&[u8], DecodeError> {
    Ok(data)
}
```

The borrow checker will ensure that no caller can hold on to that reference longer than the input buffer is around and not modified.

This would increase the performance a bit since you don't have to copy any data around.

## Code repetition

An even more advanced thing you could do in order to avoid writing out all the fields and types again in `decode_goose_pdu` is to also use `serde` for that, by implementing your own https://serde.rs/impl-deserializer.html
