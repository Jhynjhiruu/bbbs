use binrw::{binrw, BinRead, BinResult};
use hex_literal::hex;
use sha1::{Digest, Sha1};
use thiserror::Error;

use std::io::Cursor;
use std::mem::size_of;
use std::num::Wrapping;

pub type BbShaHash = [u8; 20];
pub type BbAesKey = [u8; 16];
pub type BbAesIv = [u8; 16];
pub type BbEccPrivateKey = [u8; 32];
pub type BbEccPublicKey = [u8; 64];
pub type BbId = u32;
pub type BbContentId = u32;
pub type BbServerName = [u8; 64];
pub type BbRsaSig2048 = [u8; 256];

const BOOTROM_HASH: BbShaHash = hex!("1663EFC4F08E1E20C244B38F3572325700D327C1");

pub trait HashHex {
    fn to_hex(&self) -> String;
}

impl HashHex for BbShaHash {
    fn to_hex(&self) -> String {
        self.map(|b| format!("{b:02X}")).join("")
    }
}

#[binrw]
#[derive(Debug)]
pub struct Virage2 {
    pub sk_hash: BbShaHash,

    pub rom_patch: [u32; Self::NUM_ROM_PATCH_WORDS],

    pub pub_key: BbEccPublicKey,

    pub bbid: BbId,

    pub priv_key: BbEccPrivateKey,

    pub boot_app_key: BbAesKey,
    pub recrypt_list_key: BbAesKey,
    pub app_state_key: BbAesKey,
    pub self_msg_key: BbAesKey,

    pub csum_adjust: u32,

    pub jtag_enable: u32,
}

impl Virage2 {
    const NUM_ROM_PATCH_WORDS: usize = 16;

    const SIZE: usize = 256;

    const CSUM_MAGIC: u32 = 0x00BBC0DE;

    pub fn read_from_buf(buf: &[u8]) -> BinResult<Self> {
        if buf.len() != Self::SIZE {
            return Err(binrw::Error::AssertFail {
                pos: 0,
                message: format!(
                    "incorrect size (got {} bytes, expected {})",
                    buf.len(),
                    Self::SIZE
                ),
            });
        }

        let csum: Wrapping<_> = buf
            .chunks_exact(4)
            .map(|i| u32::from_be_bytes(i.try_into().unwrap()))
            .map(Wrapping)
            .sum();

        if csum.0 != Self::CSUM_MAGIC {
            return Err(binrw::Error::BadMagic {
                pos: 0,
                found: Box::new(format!(
                    "Invalid checksum (got {:08X}, expected {:08X})",
                    csum.0,
                    Self::CSUM_MAGIC
                )),
            });
        }

        let mut cursor = Cursor::new(buf);
        <_>::read_be(&mut cursor)
    }
}

#[derive(Debug, Error)]
pub enum BootromError {
    #[error("Invalid bootrom SHA-1 hash (got {0}, expected {})", BOOTROM_HASH.to_hex())]
    InvalidHash(String),
}

pub const SK_KEY_START: usize = 0x1460;
pub const SK_IV_START: usize = 0x1470;

pub fn bootrom_keys(bootrom: &[u8]) -> Result<(BbAesKey, BbAesIv), BootromError> {
    let mut hasher = Sha1::new();

    hasher.update(bootrom);

    let bootrom_hash: BbShaHash = hasher.finalize().into();

    if bootrom_hash != BOOTROM_HASH {
        return Err(BootromError::InvalidHash(bootrom_hash.to_hex()));
    }

    let sk_key = bootrom[SK_KEY_START..SK_KEY_START + size_of::<BbAesKey>()]
        .try_into()
        .unwrap();
    let sk_iv = bootrom[SK_IV_START..SK_IV_START + size_of::<BbAesIv>()]
        .try_into()
        .unwrap();

    Ok((sk_key, sk_iv))
}

#[binrw]
#[derive(Debug)]
pub struct CmdHead {
    #[brw(pad_before(4))]
    pub ca_crl_version: u32,
    pub cp_crl_version: u32,

    pub size: u32,
    pub desc_flags: u32,
    pub common_cmd_iv: BbAesIv,

    pub hash: BbShaHash,
    pub iv: BbAesIv,

    pub exec_flags: u32,
    pub hw_access_rights: u32,
    pub secure_kernel_rights: u32,

    pub bbid: u32,

    pub issuer: BbServerName,

    pub id: BbContentId,
    pub key: BbAesKey,

    pub content_meta_data_sign: BbRsaSig2048,
}

impl CmdHead {
    pub const SIZE: usize = 0x1AC;

    pub fn read_from_buf(buf: &[u8]) -> BinResult<Self> {
        if buf.len() != Self::SIZE {
            return Err(binrw::Error::AssertFail {
                pos: 0,
                message: format!(
                    "incorrect size (got {} bytes, expected {})",
                    buf.len(),
                    Self::SIZE
                ),
            });
        }

        // maybe check the signature, eventually

        let mut cursor = Cursor::new(buf);
        <_>::read_be(&mut cursor)
    }
}
