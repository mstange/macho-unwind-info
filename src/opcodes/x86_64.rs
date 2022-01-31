use std::fmt::Display;

use crate::consts::*;
use super::bitfield::OpcodeBitfield;
use super::permutation::decode_permutation_6;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RegisterNameX86_64 {
    Rbx,
    R12,
    R13,
    R14,
    R15,
    Rbp,
}

impl RegisterNameX86_64 {
    pub fn parse(n: u8) -> Option<Self> {
        match n {
            1 => Some(RegisterNameX86_64::Rbx),
            2 => Some(RegisterNameX86_64::R12),
            3 => Some(RegisterNameX86_64::R13),
            4 => Some(RegisterNameX86_64::R14),
            5 => Some(RegisterNameX86_64::R15),
            6 => Some(RegisterNameX86_64::Rbp),
            _ => None,
        }
    }

    pub fn dwarf_name(&self) -> &'static str {
        match self {
            RegisterNameX86_64::Rbx => "reg3",
            RegisterNameX86_64::R12 => "reg12",
            RegisterNameX86_64::R13 => "reg13",
            RegisterNameX86_64::R14 => "reg14",
            RegisterNameX86_64::R15 => "reg15",
            RegisterNameX86_64::Rbp => "reg6",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpcodeX86_64 {
    Null,
    FrameBased {
        stack_offset_in_bytes: u16,
        saved_regs: [Option<RegisterNameX86_64>; 5],
    },
    FramelessImmediate {
        stack_size_in_bytes: u16,
        saved_regs: [Option<RegisterNameX86_64>; 6],
    },
    FramelessIndirect,
    Dwarf {
        eh_frame_fde: u32,
    },
}

impl OpcodeX86_64 {
    pub fn parse(opcode: u32) -> Option<Self> {
        let opcode = match OpcodeBitfield::new(opcode).kind() {
            OPCODE_KIND_NULL => OpcodeX86_64::Null,
            OPCODE_KIND_X86_FRAMEBASED => OpcodeX86_64::FrameBased {
                stack_offset_in_bytes: (((opcode >> 16) & 0xff) as u16) * 8,
                saved_regs: [
                    RegisterNameX86_64::parse(((opcode >> 12) & 0b111) as u8),
                    RegisterNameX86_64::parse(((opcode >> 9) & 0b111) as u8),
                    RegisterNameX86_64::parse(((opcode >> 6) & 0b111) as u8),
                    RegisterNameX86_64::parse(((opcode >> 3) & 0b111) as u8),
                    RegisterNameX86_64::parse((opcode & 0b111) as u8),
                ],
            },
            OPCODE_KIND_X86_FRAMELESS_IMMEDIATE => {
                let stack_size_in_bytes = (((opcode >> 16) & 0xff) as u16) * 8;
                let register_count = (opcode >> 10) & 0b111;
                let register_permutation = opcode & 0b11_1111_1111;
                let saved_registers =
                    decode_permutation_6(register_count, register_permutation).ok()?;
                OpcodeX86_64::FramelessImmediate {
                    stack_size_in_bytes,
                    saved_regs: [
                        RegisterNameX86_64::parse(saved_registers[0]),
                        RegisterNameX86_64::parse(saved_registers[1]),
                        RegisterNameX86_64::parse(saved_registers[2]),
                        RegisterNameX86_64::parse(saved_registers[3]),
                        RegisterNameX86_64::parse(saved_registers[4]),
                        RegisterNameX86_64::parse(saved_registers[5]),
                    ],
                }
            }
            OPCODE_KIND_X86_FRAMELESS_INDIRECT => OpcodeX86_64::FramelessIndirect,
            OPCODE_KIND_X86_DWARF => OpcodeX86_64::Dwarf {
                eh_frame_fde: (opcode & 0xffffff),
            },
            _ => return None,
        };
        Some(opcode)
    }
}

impl Display for OpcodeX86_64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpcodeX86_64::Null => {
                write!(f, "(uncovered)")?;
            }
            OpcodeX86_64::FrameBased {
                stack_offset_in_bytes,
                saved_regs,
            } => {
                // rbp was set to rsp before the saved registers were pushed.
                // The first pushed register is at rbp - 8 (== CFA - 24), the last at rbp - stack_offset_in_bytes.
                write!(f, "CFA=reg6+16: reg6=[CFA-16], reg16=[CFA-8]")?;
                let max_count = (*stack_offset_in_bytes / 8) as usize;
                let mut offset = *stack_offset_in_bytes + 16; // + 2 for rbp, return address
                for reg in saved_regs.iter().rev().take(max_count) {
                    if let Some(reg) = reg {
                        write!(f, ", {}=[CFA-{}]", reg.dwarf_name(), offset)?;
                    }
                    offset -= 8;
                }
            }
            OpcodeX86_64::FramelessImmediate {
                stack_size_in_bytes,
                saved_regs,
            } => {
                if *stack_size_in_bytes == 0 {
                    write!(f, "CFA=reg7:",)?;
                } else {
                    write!(f, "CFA=reg7+{}:", *stack_size_in_bytes)?;
                }
                write!(f, " reg16=[CFA-8]")?;
                let mut offset = 2 * 8;
                for reg in saved_regs.iter().rev().flatten() {
                    write!(f, ", {}=[CFA-{}]", reg.dwarf_name(), offset)?;
                    offset += 8;
                }
            }
            OpcodeX86_64::FramelessIndirect { .. } => {
                write!(f, "frameless indirect")?;
            }
            OpcodeX86_64::Dwarf { eh_frame_fde } => {
                write!(f, "(check eh_frame FDE 0x{:x})", eh_frame_fde)?;
            }
        }
        Ok(())
    }
}
