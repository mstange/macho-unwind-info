[![crates.io page](https://img.shields.io/crates/v/macho-unwind-info.svg)](https://crates.io/crates/macho-unwind-info)
[![docs.rs page](https://docs.rs/macho-unwind-info/badge.svg)](https://docs.rs/macho-unwind-info/)

# macho-unwind-info

A zero-copy parser for the contents of the `__unwind_info` section of a mach-O binary.

Quickly look up the unwinding opcode for an address.

This crate is intended to be fast enough to be used in a sampling profiler. Re-parsing from scratch is cheap and can be done on every sample.

## Example

```rust
use macho_unwind_info::{UnwindInfo, OpcodeX86_64};

let unwind_info = UnwindInfo::parse(data)?;
if let Some(function) = unwind_info.lookup(0x1234)? {
    match OpcodeX86_64::parse(function.opcode) {
        OpcodeX86_64::Null => println!("Null"),
        OpcodeX86_64::FrameBased { .. } => println!("FrameBased"),
        OpcodeX86_64::FramelessImmediate { .. } => println!("FramelessImmediate"),
        OpcodeX86_64::FramelessIndirect => println!("FramelessIndirect"),
        OpcodeX86_64::Dwarf { .. } => println!("Dwarf"),
    }
}
```

## Command-line usage

This repository also contains two CLI executables. You can install them like so:

```
% cargo install --examples macho-unwind-info
```

## Credits

Thanks a ton to @Gankra for documenting this format at https://gankra.github.io/blah/compact-unwinding/.

## License

Licensed under either of

  * Apache License, Version 2.0 ([`LICENSE-APACHE`](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
  * MIT license ([`LICENSE-MIT`](./LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
