![](https://github.com/zer0x64/pbkdf2-identifier/workflows/Build/badge.svg)
# PBKDF2-identifier

This is a tool to identify the parameters used to generate a PBKDF2 hash. Useful to defeat the good old "Security by Obscurity".
It is able to determine the number of iteration and the underlying algorithm. This currently supports `HMAC-SHA1`, `HMAC-SHA256` and `HMAC-SHA512`. Also, this will eventually be multithreaded when not in webassembly.
This will also eventually be made as a webassembly module.

# How to use
If you don't know the algorithm:
```
pbkdf2-identifier -p password123 -m 1000 -H ir/kfDpM5af8tVwGbeRgDA== -s L1q4pm5kD3cu1G9ByIx5Lw==
```
If you already know the algorithm:
```
pbkdf2-identifier -p password123 -m 1000 -H 8abfe47c3a4ce5a7fcb55c066de4600c -s 2f5ab8a66e640f772ed46f41c88c792f -f hex -a HMAC-SHA512
```

## License

This project is licensed under either of
- Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

## Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in pbkdf2-identifier by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
