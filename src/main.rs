use anyhow::Result;

fn main() -> Result<()> {
    let args = bbbs::args::parse_args();

    bbbs::build(args)
}
