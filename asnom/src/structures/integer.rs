use common::TagClass;
use super::ASNTag;
use universal;
use structure;

use std::default;

use byteorder::{BigEndian, WriteBytesExt};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Integer {
    pub id: u64,
    pub class: TagClass,
    pub inner: i64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Enumerated {
    pub id: u64,
    pub class: TagClass,
    pub inner: i64,
}

fn i_e_into_structure(id: u64, class: TagClass, inner: i64) -> structure::StructureTag {
    let mut count = 0u8;
    let mut rem: i64 = if inner >= 0 { inner } else { inner * -1 };
    while {count += 1; rem >>= 8; rem > 0 }{}

    let mut out: Vec<u8> = Vec::with_capacity(count as usize);

    out.write_int::<BigEndian>(inner, count as usize).unwrap();

    structure::StructureTag {
        id: id,
        class: class,
        payload: structure::PL::P(out),
    }
}

impl ASNTag for Integer {
    fn into_structure(self) -> structure::StructureTag {
        i_e_into_structure(self.id, self.class, self.inner)
    }
}

impl ASNTag for Enumerated {
    fn into_structure(self) -> structure::StructureTag {
        i_e_into_structure(self.id, self.class, self.inner)
    }
}

impl default::Default for Integer {
    fn default() -> Integer {
        Integer {
            id: universal::Types::Integer as u64,
            class: TagClass::Universal,
            inner: 0i64,
        }
    }
}

impl default::Default for Enumerated {
    fn default() -> Enumerated {
        Enumerated {
            id: universal::Types::Enumerated as u64,
            class: TagClass::Universal,
            inner: 0i64,
        }
    }
}
