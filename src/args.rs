use anyhow::Result;
use clap::Parser;

use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
use std::fs::{read, read_to_string, write};
use std::io::{stdout, Error, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum IOType {
    Stdin,
    Stdout,
    File(PathBuf),
}

impl IOType {
    pub fn read(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Stdin => {
                let mut rv = vec![];
                std::io::stdin().lock().read_to_end(&mut rv)?;
                Ok(rv)
            }
            Self::Stdout => Err(Error::from(ErrorKind::Unsupported)),
            Self::File(path) => read(path),
        }
        .map_err(|e| Error::new(e.kind(), format!("{} ({})", e, self)))
    }

    pub fn read_string(&self) -> Result<String, Error> {
        match self {
            Self::Stdin => {
                let mut rv = String::new();
                std::io::stdin().lock().read_to_string(&mut rv)?;
                Ok(rv)
            }
            Self::Stdout => Err(Error::from(ErrorKind::Unsupported)),
            Self::File(path) => read_to_string(path),
        }
        .map_err(|e| Error::new(e.kind(), format!("{} ({})", e, self)))
    }

    pub fn write<T: AsRef<[u8]>>(&self, data: T) -> Result<usize, Error> {
        match self {
            Self::Stdin => Err(Error::from(ErrorKind::Unsupported)),
            Self::Stdout => stdout().write(data.as_ref()),
            Self::File(path) => write(path, &data).and(Ok(data.as_ref().len())),
        }
    }

    fn input<T: AsRef<str>>(path: T) -> Self {
        match path.as_ref() {
            "-" => Self::Stdin,
            p => Self::File(PathBuf::from(p)),
        }
    }

    fn output<T: AsRef<str>>(path: T) -> Self {
        match path.as_ref() {
            "-" => Self::Stdout,
            p => Self::File(PathBuf::from(p)),
        }
    }

    fn derive_input<F: FnOnce(&PathBuf) -> PathBuf>(&self, f: F) -> Self {
        match self {
            Self::Stdin => Self::Stdin,
            Self::Stdout => Self::Stdin,
            Self::File(p) => Self::File(f(p)),
        }
    }

    fn derive_output<F: FnOnce(&PathBuf) -> PathBuf>(&self, f: F) -> Self {
        match self {
            Self::Stdin => Self::Stdout,
            Self::Stdout => Self::Stdout,
            Self::File(p) => Self::File(f(p)),
        }
    }
}

impl Display for IOType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Stdin => "stdin".to_string(),
                Self::Stdout => "stdout".to_string(),
                Self::File(f) => f.display().to_string(),
            }
        )
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Payload; "-" for stdin
    #[arg(default_value_t = String::from("-"))]
    infile: String,

    /// Input SKSA
    #[arg(short, long)]
    sksa: String,

    /// Input Virage2 (used for key derivation)
    #[arg(short, long)]
    virage2: String,

    /// Input bootrom (used for key derivation)
    #[arg(short, long)]
    bootrom: String,

    /// Output BBBS SKSA; "-" for stdout [default: <infile>.sksa or -]
    outfile: Option<String>,
}

#[derive(Debug)]
pub struct Args {
    pub infile: IOType,
    pub sksa: IOType,
    pub virage2: IOType,
    pub bootrom: IOType,
    pub outfile: IOType,
}

impl From<Cli> for Args {
    fn from(value: Cli) -> Self {
        fn replace_extension_or(orig: &Path, replace: &[&str], with: &str) -> PathBuf {
            match orig.extension() {
                Some(_)
                    if replace.iter().map(OsString::from).any(|s| {
                        s.to_ascii_lowercase() == orig.extension().unwrap().to_ascii_lowercase()
                    }) =>
                {
                    orig.with_extension(with)
                }
                None => orig.with_extension(with),
                _ => {
                    let mut s = orig.as_os_str().to_owned();
                    s.push(format!(".{with}"));
                    s.into()
                }
            }
        }

        let infile = IOType::input(value.infile);
        let sksa = IOType::input(value.sksa);
        let virage2 = IOType::input(value.virage2);
        let bootrom = IOType::input(value.bootrom);
        let outfile = match value.outfile {
            Some(f) => IOType::output(f),
            None => infile.derive_output(|p| replace_extension_or(p, &["bin"], "sksa")),
        };

        Self {
            infile,
            sksa,
            virage2,
            bootrom,
            outfile,
        }
    }
}

pub fn parse_args() -> Args {
    Cli::parse().into()
}
