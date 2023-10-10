use std::path::{Path, PathBuf};
use std::process::Command;

static AFL_SRC_PATH: &str = "AFLplusplus";

// https://github.com/rust-fuzz/afl.rs/issues/148
#[cfg(target_os = "macos")]
static AR_CMD: &str = "/usr/bin/ar";
#[cfg(not(target_os = "macos"))]
static AR_CMD: &str = "ar";

#[path = "src/common.rs"]
mod common;

fn main() {
    let work_dir = PathBuf::from(AFL_SRC_PATH);

    let base: Option<&Path> = None;

    // smoelius: Lock `work_dir` until the build script exits.
    #[cfg(unix)]
    let _file = sys::lock_path(&work_dir).unwrap();

    let mut llvm_config = String::new();

    if cfg!(feature = "cmplog") {
        llvm_config = common::get_llvm_config();
    }

    build_afl(&work_dir, base, llvm_config);

    if cfg!(feature = "cmplog") {
        build_afl_llvm_runtime(&work_dir, base);
    }
}

fn build_afl(work_dir: &Path, base: Option<&Path>, llvm_config: String) {
    if cfg!(feature = "cmplog") {
        // Make sure we are on nightly for the -Z flags
        assert!(
            rustc_version::version_meta().unwrap().channel == rustc_version::Channel::Nightly,
            "cargo-afl must be compiled with nightly for the cmplog feature"
        );

        // check if llvm tools are installed and with the good version for the plugin compilation
        let mut command = Command::new(llvm_config.clone());
        command.args(["--version"]);
        let status = command
            .status()
            .unwrap_or_else(|_| panic!("could not run {llvm_config} --version"));
        assert!(status.success());
    }

    // if you had already installed cargo-afl previously you **must** clean AFL++
    let mut command = Command::new("make");
    command
        .current_dir(work_dir)
        .args(["clean"])
        // skip the checks for the legacy x86 afl-gcc compiler
        .env("AFL_NO_X86", "1")
        // build just the runtime to avoid troubles with Xcode clang on macOS
        //.env("NO_BUILD", "1")
        .env("DESTDIR", common::afl_dir(base))
        .env("PREFIX", "")
        .env("LLVM_CONFIG", llvm_config.clone())
        .env_remove("DEBUG");

    let status = command.status().expect("could not run 'make clean'");
    assert!(status.success());

    let mut command = Command::new("make");
    command
        .current_dir(work_dir)
        .args(["install"])
        // skip the checks for the legacy x86 afl-gcc compiler
        .env("AFL_NO_X86", "1")
        // build just the runtime to avoid troubles with Xcode clang on macOS
        //.env("NO_BUILD", "1")
        .env("DESTDIR", common::afl_dir(base))
        .env("PREFIX", "")
        .env("LLVM_CONFIG", llvm_config)
        .env_remove("DEBUG");
    let status = command.status().expect("could not run 'make install'");
    assert!(status.success());
}

fn build_afl_llvm_runtime(work_dir: &Path, base: Option<&Path>) {
    std::fs::copy(
        work_dir.join("afl-compiler-rt.o"),
        common::object_file_path(base),
    )
    .expect("Couldn't copy object file");

    let shared_libraries = [
        "afl-llvm-dict2file.so",
        "afl-llvm-pass.so",
        "cmplog-instructions-pass.so",
        "cmplog-routines-pass.so",
        "cmplog-switches-pass.so",
        "compare-transform-pass.so",
        "split-compares-pass.so",
        "split-switches-pass.so",
        "SanitizerCoveragePCGUARD.so",
    ];

    for sl in shared_libraries {
        std::fs::copy(work_dir.join(sl), common::afl_llvm_dir(base).join(sl))
            .unwrap_or_else(|_| panic!("Couldn't copy shared object file {sl}"));
    }

    let status = Command::new(AR_CMD)
        .arg("r")
        .arg(common::archive_file_path(base))
        .arg(common::object_file_path(base))
        .status()
        .expect("could not run 'ar'");
    assert!(status.success());
}

#[cfg(unix)]
mod sys {
    use std::fs::File;
    use std::io::{Error, Result};
    use std::os::unix::io::AsRawFd;
    use std::path::Path;

    pub fn lock_path(path: &Path) -> Result<File> {
        let file = File::open(path)?;
        lock_exclusive(&file)?;
        Ok(file)
    }

    // smoelius: `lock_exclusive` and `flock` were copied from:
    // https://github.com/rust-lang/cargo/blob/ae91d4ed41da98bdfa16041dbc6cd30287920120/src/cargo/util/flock.rs

    fn lock_exclusive(file: &File) -> Result<()> {
        flock(file, libc::LOCK_EX)
    }

    fn flock(file: &File, flag: libc::c_int) -> Result<()> {
        let ret = unsafe { libc::flock(file.as_raw_fd(), flag) };
        if ret < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
