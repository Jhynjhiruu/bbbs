use anyhow::Result;
use bb::{bootrom_keys, BbShaHash, CmdHead, HashHex, Virage2};
use sha1::{Digest, Sha1};
use soft_aes::aes::{aes_dec_cbc, aes_enc_cbc};
use thiserror::Error;

use std::{error::Error as StdError, mem::size_of};

pub mod args;

use args::Args;

const SK_SIZE: usize = 64 * 1024;
const SA1_CMD_HEAD_SIZE: usize = CmdHead::SIZE;
const SA1_INFO_BLOCK_SIZE: usize = 16 * 1024;
const SKSA_MIN_BYTES: usize = SK_SIZE + SA1_INFO_BLOCK_SIZE;

const ROM_HEADER_SIZE: usize = 4 * 1024;
const ENTRYPOINT_OFFSET: usize = 2 * size_of::<u32>();

const UNZIP_BUF_OFFSET: u32 = 0x80300000;

#[derive(Debug, Error)]
pub enum BBBSError {
    #[error("Provided SKSA is too short (got 0x{0:X} bytes, expected 0x{SKSA_MIN_BYTES:X})")]
    SKSATooShort(usize),

    #[error(
        "Provided payload is too long to fit in the provided SA1 (got 0x{0:X} bytes, max 0x{1:X})"
    )]
    PayloadTooLong(usize, u32),

    #[error("Invalid SK hash (got {0}, expected {1}")]
    InvalidSKHash(String, String),
}

impl BBBSError {
    fn from_hashes(calculated: BbShaHash, expected: BbShaHash) -> Self {
        Self::InvalidSKHash(calculated.to_hex(), expected.to_hex())
    }
}

pub fn make_sa1(payload: Vec<u8>) -> Vec<u8> {
    let mut rv = vec![0; ROM_HEADER_SIZE];

    rv[ENTRYPOINT_OFFSET..ENTRYPOINT_OFFSET + 4].copy_from_slice(&UNZIP_BUF_OFFSET.to_be_bytes());

    rv.extend(payload);

    rv
}

pub fn build(args: Args) -> Result<()> {
    let infile = args.infile.read()?;

    let sksa = args.sksa.read()?;

    if sksa.len() < SKSA_MIN_BYTES {
        return Err(BBBSError::SKSATooShort(sksa.len()).into());
    }

    let sk = &sksa[0..SK_SIZE];
    let cmd = &sksa[SK_SIZE..SK_SIZE + SA1_CMD_HEAD_SIZE];
    let cmd = CmdHead::read_from_buf(cmd)?;

    if infile.len() > cmd.size as usize - ROM_HEADER_SIZE {
        return Err(
            BBBSError::PayloadTooLong(infile.len(), cmd.size - ROM_HEADER_SIZE as u32).into(),
        );
    }

    let virage2 = args.virage2.read()?;
    let virage2 = Virage2::read_from_buf(&virage2)?;

    let bootrom = args.bootrom.read()?;

    let (sk_key, sk_iv) = bootrom_keys(&bootrom)?;

    let sk = aes_dec_cbc(sk, &sk_key, &sk_iv, None).expect("decryption failed");

    let mut hasher = Sha1::new();

    hasher.update(sk);

    let sk_hash = hasher.finalize();

    if sk_hash[..] != virage2.sk_hash {
        return Err(BBBSError::from_hashes(sk_hash.into(), virage2.sk_hash).into());
    }

    let sa1_key = aes_dec_cbc(&cmd.key, &virage2.boot_app_key, &cmd.common_cmd_iv, None)
        .expect("decryption failed");

    let mut sa1 = make_sa1(infile);
    sa1.resize(cmd.size as _, 0);

    let sa1_enc = aes_enc_cbc(&sa1, &sa1_key, &cmd.iv, None).expect("encryption failed");

    let mut outfile = vec![];
    outfile.extend(&sksa[0..SKSA_MIN_BYTES]);
    outfile.extend(sa1_enc);

    args.outfile.write(outfile)?;

    Ok(())
}
