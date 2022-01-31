[![crates.io page](https://img.shields.io/crates/v/macho-unwind-info.svg)](https://crates.io/crates/macho-unwind-info)
[![docs.rs page](https://docs.rs/macho-unwind-info/badge.svg)](https://docs.rs/macho-unwind-info/)

# macho-unwind-info

A zero-copy parser for the contents of the `__unwind_info` section of a
mach-O binary.

Quickly look up the unwinding opcode for an address. Then parse the opcode to find
out how to recover the return address and the caller frame's register values.

This crate is intended to be fast enough to be used in a sampling profiler.
Re-parsing from scratch is cheap and can be done on every sample.

# Example

```rust
use macho_unwind_info::UnwindInfo;
use macho_unwind_info::opcodes::OpcodeX86_64;

let unwind_info = UnwindInfo::parse(data)?;

if let Some(function) = unwind_info.lookup(0x1234)? {
    println!("Found function entry covering the address 0x1234:");
    let opcode = OpcodeX86_64::parse(function.opcode);
    println!("0x{:08x}..0x{:08x}: {}", function.start_address, function.end_address, opcode);
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
