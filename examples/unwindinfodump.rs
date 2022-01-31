use std::{fmt::Display, fs::File, io::Read};

use macho_unwind_info::{OpcodeArm64, OpcodeBitfield, OpcodeX86, OpcodeX86_64, UnwindInfo};
use object::{Architecture, ObjectSection};

fn main() {
    let mut args = std::env::args_os().skip(1);
    if args.len() < 1 {
        eprintln!("Usage: {} <path>", std::env::args().next().unwrap());
        std::process::exit(1);
    }
    let path = args.next().unwrap();

    let mut data = Vec::new();
    let mut file = File::open(path).unwrap();
    file.read_to_end(&mut data).unwrap();
    let data = &data[..];

    let file = object::File::parse(data).expect("Could not parse object file");
    use object::Object;
    let unwind_info_data_section = file
        .section_by_name_bytes(b"__unwind_info")
        .expect("Could not find __unwind_info section");
    let data = unwind_info_data_section.data().unwrap();
    let arch = file.architecture();

    let info = UnwindInfo::parse(data).unwrap();
    let mut page_iter = info.pages();
    while let Some(page) = page_iter.next().unwrap() {
        println!(
            "0x{:08x}..0x{:08x} Page",
            page.start_address(),
            page.end_address()
        );
        for function in page.functions() {
            print_entry(function.start_address, function.opcode, arch);
        }
        println!();
    }
}

fn print_entry(address: u32, opcode: u32, arch: Architecture) {
    let kind = OpcodeBitfield::new(opcode).kind();
    match arch {
        Architecture::I386 => {
            print_entry_impl(address, OpcodeX86::parse(opcode), kind);
        }
        Architecture::X86_64 => {
            print_entry_impl(address, OpcodeX86_64::parse(opcode), kind);
        }
        Architecture::Aarch64 => {
            print_entry_impl(address, OpcodeArm64::parse(opcode), kind);
        }
        _ => {}
    }
}

fn print_entry_impl(address: u32, opcode: Option<impl Display>, kind: u8) {
    match opcode {
        Some(opcode) => println!("  0x{:08x}: {}", address, opcode),
        None => println!("  0x{:08x}: unknown opcode kind {}", address, kind),
    }
}
