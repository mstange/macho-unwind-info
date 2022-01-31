mod error;
mod num_display;
pub mod opcodes;
pub mod raw;
mod reader;

pub use error::Error;
use raw::*;

pub struct UnwindInfo<'a>(PartialPages<'a>);

#[derive(Clone, Copy)]
struct PartialPages<'a> {
    data: &'a [u8],
    global_opcodes: &'a [Opcode],
    pages: &'a [PageEntry],
}

impl<'a> UnwindInfo<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let header = CompactUnwindInfoHeader::parse(data)?;
        let global_opcodes = header.global_opcodes(data)?;
        let pages = header.pages(data)?;
        Ok(Self(PartialPages {
            data,
            global_opcodes,
            pages,
        }))
    }

    pub fn pages(&self) -> PageIter<'a> {
        PageIter(self.0)
    }

    pub fn lookup(&self, pc: u32) -> Result<Option<Function>, Error> {
        let PartialPages {
            pages,
            data,
            global_opcodes,
        } = self.0;
        let page_index = match pages.binary_search_by_key(&pc, PageEntry::first_address) {
            Ok(i) => i,
            Err(insertion_index) => {
                if insertion_index == 0 {
                    return Ok(None);
                }
                insertion_index - 1
            }
        };
        if page_index == pages.len() - 1 {
            // We found the sentinel last page, which just marks the end of the range.
            // So the looked up address is at or after the end address, i.e. outside the
            // range of addresses covered by this UnwindInfo.
            return Ok(None);
        }
        let page_entry = &pages[page_index];
        let next_page_entry = &pages[page_index + 1];
        let page_offset = page_entry.page_offset();
        match page_entry.page_kind(data)? {
            consts::PAGE_KIND_REGULAR => {
                let page = RegularPage::parse(data, page_offset.into())?;
                let functions = page.functions(data, page_offset)?;
                let function_index =
                    match functions.binary_search_by_key(&pc, RegularFunctionEntry::address) {
                        Ok(i) => i,
                        Err(insertion_index) => {
                            if insertion_index == 0 {
                                return Err(Error::InvalidPageEntryFirstAddress);
                            }
                            insertion_index - 1
                        }
                    };
                let entry = &functions[function_index];
                let fun_address = entry.address();
                let next_fun_address = if let Some(next_entry) = functions.get(function_index + 1) {
                    next_entry.address()
                } else {
                    next_page_entry.first_address()
                };
                Ok(Some(Function {
                    start_address: fun_address,
                    end_address: next_fun_address,
                    opcode: entry.opcode(),
                }))
            }
            consts::PAGE_KIND_COMPRESSED => {
                let page = CompressedPage::parse(data, page_offset.into())?;
                let functions = page.functions(data, page_offset)?;
                let page_address = page_entry.first_address();
                let rel_pc = pc - page_address;
                let function_index = match functions.binary_search_by_key(&rel_pc, |&entry| {
                    CompressedFunctionEntry::new(entry.into()).relative_address()
                }) {
                    Ok(i) => i,
                    Err(insertion_index) => {
                        if insertion_index == 0 {
                            return Err(Error::InvalidPageEntryFirstAddress);
                        }
                        insertion_index - 1
                    }
                };

                let entry = CompressedFunctionEntry::new(functions[function_index].into());
                let fun_address = page_address + entry.relative_address();
                let next_fun_address = if let Some(next_entry) = functions.get(function_index + 1) {
                    let next_entry = CompressedFunctionEntry::new((*next_entry).into());
                    page_address + next_entry.relative_address()
                } else {
                    next_page_entry.first_address()
                };

                let opcode_index: usize = entry.opcode_index().into();
                let opcode = if opcode_index < global_opcodes.len() {
                    global_opcodes[opcode_index].opcode()
                } else {
                    let local_opcodes = page.local_opcodes(data, page_offset)?;
                    let local_index = opcode_index - global_opcodes.len();
                    local_opcodes[local_index].opcode()
                };
                Ok(Some(Function {
                    start_address: fun_address,
                    end_address: next_fun_address,
                    opcode,
                }))
            }
            consts::PAGE_KIND_SENTINEL => {
                // Only the last page should be a sentinel page, and we've already checked earlier
                // that we're not in the last page.
                Err(Error::UnexpectedSentinelPage)
            }
            _ => Err(Error::InvalidPageKind),
        }
    }
}

pub struct PageIter<'a>(PartialPages<'a>);

impl<'a> PageIter<'a> {
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Page<'a>>, Error> {
        let (page_entry, remainder) = match self.0.pages.split_first() {
            Some(split) => split,
            None => return Ok(None),
        };

        self.0.pages = remainder;

        let next_page_entry = match remainder.first() {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let page_offset = page_entry.page_offset();
        let page_address = page_entry.first_address();
        let next_page_address = next_page_entry.first_address();
        let data = self.0.data;
        match page_entry.page_kind(data)? {
            consts::PAGE_KIND_REGULAR => {
                let page = RegularPage::parse(data, page_offset.into())?;
                Ok(Some(Page(PartialFunctions::Regular {
                    page_address,
                    functions: page.functions(data, page_offset)?,
                    next_page_address,
                })))
            }
            consts::PAGE_KIND_COMPRESSED => {
                let page = CompressedPage::parse(data, page_offset.into())?;
                Ok(Some(Page(PartialFunctions::Compressed {
                    page_address,
                    next_page_address,
                    functions: page.functions(data, page_offset)?,
                    local_opcodes: page.local_opcodes(data, page_offset)?,
                    global_opcodes: self.0.global_opcodes,
                })))
            }
            consts::PAGE_KIND_SENTINEL => Err(Error::UnexpectedSentinelPage),
            _ => Err(Error::InvalidPageKind),
        }
    }
}

pub struct Page<'a>(PartialFunctions<'a>);

#[derive(Clone, Copy)]
enum PartialFunctions<'a> {
    Regular {
        page_address: u32,
        functions: &'a [RegularFunctionEntry],
        next_page_address: u32,
    },
    Compressed {
        page_address: u32,
        functions: &'a [U32],
        local_opcodes: &'a [Opcode],
        global_opcodes: &'a [Opcode],
        next_page_address: u32,
    },
}

impl<'a> Page<'a> {
    pub fn start_address(&self) -> u32 {
        match self.0 {
            PartialFunctions::Regular { page_address, .. } => page_address,
            PartialFunctions::Compressed { page_address, .. } => page_address,
        }
    }

    pub fn end_address(&self) -> u32 {
        match self.0 {
            PartialFunctions::Regular {
                next_page_address, ..
            } => next_page_address,
            PartialFunctions::Compressed {
                next_page_address, ..
            } => next_page_address,
        }
    }

    pub fn functions(&self) -> FunctionIter<'a> {
        FunctionIter(self.0)
    }
}

pub struct FunctionIter<'a>(PartialFunctions<'a>);

impl<'a> Iterator for FunctionIter<'a> {
    type Item = Function;

    fn next(&mut self) -> Option<Function> {
        match &mut self.0 {
            PartialFunctions::Regular {
                functions,
                next_page_address,
                ..
            } => {
                let (entry, remainder) = functions.split_first()?;
                *functions = remainder;
                let start_address = entry.address();
                let end_address = remainder
                    .first()
                    .map(RegularFunctionEntry::address)
                    .unwrap_or(*next_page_address);
                Some(Function {
                    start_address,
                    end_address,
                    opcode: entry.opcode(),
                })
            }
            PartialFunctions::Compressed {
                page_address,
                functions,
                next_page_address,
                local_opcodes,
                global_opcodes,
            } => {
                let (entry, remainder) = functions.split_first()?;
                *functions = remainder;
                let entry = CompressedFunctionEntry::new((*entry).into());
                let start_address = *page_address + entry.relative_address();
                let end_address = match remainder.first() {
                    Some(next_entry) => {
                        let next_entry = CompressedFunctionEntry::new((*next_entry).into());
                        *page_address + next_entry.relative_address()
                    }
                    None => *next_page_address,
                };
                let opcode_index: usize = entry.opcode_index().into();
                let opcode = if opcode_index < global_opcodes.len() {
                    global_opcodes[opcode_index].opcode()
                } else {
                    let local_index = opcode_index - global_opcodes.len();
                    local_opcodes[local_index].opcode()
                };
                Some(Function {
                    start_address,
                    end_address,
                    opcode,
                })
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Function {
    pub start_address: u32,
    pub end_address: u32,
    pub opcode: u32,
}
