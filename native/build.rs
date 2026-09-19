use std::env;
use std::fs;
use std::io;
use std::path::Path;

fn copy_tree(source: &Path, target: &Path) -> io::Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let destination = target.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &destination)?;
        } else if entry.file_type()?.is_file() {
            fs::copy(entry.path(), destination)?;
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    // Keep one maintained copy in the repository. Maturin adds this generated
    // copy to the main wheel; standalone companion builds do not need it.
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest directory");
    let source = Path::new(&manifest_dir).join("../data");
    println!("cargo:rerun-if-changed={}", source.display());
    let output_dir = env::var_os("OUT_DIR").expect("Cargo build output directory");
    let target = Path::new(&output_dir).join("_bundled_data");
    if target.exists() {
        fs::remove_dir_all(&target)?;
    }
    if source.is_dir() {
        for name in ["attack", "scheduled_tasks", "sigma_rules"] {
            copy_tree(&source.join(name), &target.join(name))?;
        }
    }
    Ok(())
}
