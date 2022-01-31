use std::fmt::Display;

use crate::consts::*;
use super::bitfield::OpcodeBitfield;
use super::permutation::decode_permutation_6;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RegisterNameX86 {
    Ebx,
    Ecx,
    Edx,
    Edi,
    Esi,
    Ebp,
}

impl RegisterNameX86 {
    pub fn parse(n: u8) -> Option<Self> {
        match n {
            1 => Some(RegisterNameX86::Ebx),
            2 => Some(RegisterNameX86::Ecx),
            3 => Some(RegisterNameX86::Edx),
            4 => Some(RegisterNameX86::Edi),
            5 => Some(RegisterNameX86::Esi),
            6 => Some(RegisterNameX86::Ebp),
            _ => None,
        }
    }

    pub fn dwarf_name(&self) -> &'static str {
        match self {
            RegisterNameX86::Ebx => "reg3",
            RegisterNameX86::Ecx => "reg1",
            RegisterNameX86::Edx => "reg2",
            RegisterNameX86::Edi => "reg7",
            RegisterNameX86::Esi => "reg6",
            RegisterNameX86::Ebp => "reg5",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OpcodeX86 {
    Null,
    FrameBased {
        stack_offset_in_bytes: u16,
        saved_regs: [Option<RegisterNameX86>; 5],
    },
    FramelessImmediate {
        stack_size_in_bytes: u16,
        saved_regs: [Option<RegisterNameX86>; 6],
    },
    FramelessIndirect,
    Dwarf {
        eh_frame_fde: u32,
    },
}

impl OpcodeX86 {
    pub fn parse(opcode: u32) -> Option<Self> {
        let opcode = match OpcodeBitfield::new(opcode).kind() {
            OPCODE_KIND_NULL => OpcodeX86::Null,
            OPCODE_KIND_X86_FRAMEBASED => OpcodeX86::FrameBased {
                stack_offset_in_bytes: (((opcode >> 16) & 0xff) as u16) * 4,
                saved_regs: [
                    RegisterNameX86::parse(((opcode >> 12) & 0b111) as u8),
                    RegisterNameX86::parse(((opcode >> 9) & 0b111) as u8),
                    RegisterNameX86::parse(((opcode >> 6) & 0b111) as u8),
                    RegisterNameX86::parse(((opcode >> 3) & 0b111) as u8),
                    RegisterNameX86::parse((opcode & 0b111) as u8),
                ],
            },
            OPCODE_KIND_X86_FRAMELESS_IMMEDIATE => {
                let stack_size_in_bytes = (((opcode >> 16) & 0xff) as u16) * 4;
                let register_count = (opcode >> 10) & 0b111;
                let register_permutation = opcode & 0b11_1111_1111;
                let saved_registers =
                    decode_permutation_6(register_count, register_permutation).ok()?;
                OpcodeX86::FramelessImmediate {
                    stack_size_in_bytes,
                    saved_regs: [
                        RegisterNameX86::parse(saved_registers[0]),
                        RegisterNameX86::parse(saved_registers[1]),
                        RegisterNameX86::parse(saved_registers[2]),
                        RegisterNameX86::parse(saved_registers[3]),
                        RegisterNameX86::parse(saved_registers[4]),
                        RegisterNameX86::parse(saved_registers[5]),
                    ],
                }
            }
            OPCODE_KIND_X86_FRAMELESS_INDIRECT => OpcodeX86::FramelessIndirect,
            OPCODE_KIND_X86_DWARF => OpcodeX86::Dwarf {
                eh_frame_fde: (opcode & 0xffffff),
            },
            _ => return None,
        };
        Some(opcode)
    }
}

impl Display for OpcodeX86 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpcodeX86::Null => {
                write!(f, "(uncovered)")?;
            }
            OpcodeX86::FrameBased {
                stack_offset_in_bytes,
                saved_regs,
            } => {
                // ebp was set to esp before the saved registers were pushed.
                // The first pushed register is at ebp - 4 (== CFA - 12), the last at ebp - stack_offset_in_bytes.
                write!(f, "CFA=reg6+8: reg6=[CFA-8], reg16=[CFA-4]")?;
                let max_count = (*stack_offset_in_bytes / 4) as usize;
                let mut offset = *stack_offset_in_bytes + 8; // + 2 for rbp, return address
                for reg in saved_regs.iter().rev().take(max_count) {
                    if let Some(reg) = reg {
                        write!(f, ", {}=[CFA-{}]", reg.dwarf_name(), offset)?;
                    }
                    offset -= 4;
                }
            }
            OpcodeX86::FramelessImmediate {
                stack_size_in_bytes,
                saved_regs,
            } => {
                if *stack_size_in_bytes == 0 {
                    write!(f, "CFA=reg7:",)?;
                } else {
                    write!(f, "CFA=reg7+{}:", *stack_size_in_bytes)?;
                }
                write!(f, " reg16=[CFA-8]")?;
                let mut offset = 2 * 4;
                for reg in saved_regs.iter().rev().flatten() {
                    write!(f, ", {}=[CFA-{}]", reg.dwarf_name(), offset)?;
                    offset += 4;
                }
            }
            OpcodeX86::FramelessIndirect { .. } => {
                write!(f, "frameless indirect")?;
            }
            OpcodeX86::Dwarf { eh_frame_fde } => {
                write!(f, "(check eh_frame FDE 0x{:x})", eh_frame_fde)?;
            }
        }
        Ok(())
    }
}
