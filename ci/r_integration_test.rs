use std::{cell::OnceCell, fs::File, path::PathBuf, process::Command, sync::Mutex};

use gtfsort::{current_func, interop::r_ffi::RObj, test_utils::*};
use libR_sys::{
    setup_Rmainloop, R_CStackLimit, R_GlobalEnv, R_tryEval, Rf_ScalarString, Rf_initialize_R,
    Rf_install, Rf_lang2, Rf_lang3, Rf_mkCharCE, Rf_mkCharLenCE, Rf_unprotect, CDR, SET_TAG,
};

static mut R_INITIALIZED: OnceCell<Result<(), &'static str>> = OnceCell::new();

static R_LOCK: Mutex<()> = Mutex::new(());

fn ensure_r_init() -> Result<(), &'static str> {
    let lock = R_LOCK.lock().unwrap();
    unsafe {
        let r = R_INITIALIZED.get_or_init(|| {
            if std::env::var("R_HOME").is_err() {
                let out = Command::new("R")
                    .arg("-s")
                    .arg("-e")
                    .arg("cat(normalizePath(R.home()))")
                    .output();
                match out {
                    Ok(out) => {
                        let home = String::from_utf8(out.stdout).unwrap();
                        std::env::set_var("R_HOME", home.trim());
                    }
                    Err(_) => {
                        return Err("Failed to find R_HOME");
                    }
                }
            }
            if Rf_initialize_R(
                3,
                ["R\0".as_ptr(), "--slave\0".as_ptr(), "--silent\0".as_ptr()].as_ptr()
                    as *mut *mut i8,
            ) != 0
            {
                return Err("Failed to initialize R");
            }
            R_CStackLimit = usize::MAX;
            setup_Rmainloop();
            let test_prelude = include_str!("check_r_prelude.R");
            let prelude = Rf_mkCharLenCE(
                test_prelude.as_ptr() as *const i8,
                i32::try_from(test_prelude.len()).unwrap(),
                libR_sys::cetype_t::CE_UTF8,
            );
            let prelude = RObj::protect(prelude);
            let prelude_str = Rf_ScalarString(*prelude);
            let prelude_str = RObj::protect(prelude_str);
            let parse_call = Rf_lang2(Rf_install("parse\0".as_ptr() as *const i8), *prelude_str);
            let parse_call = RObj::protect(parse_call);
            SET_TAG(CDR(*parse_call), Rf_install("text\0".as_ptr() as *const i8));
            let mut error_occurred = 0;
            let prelude_expr = R_tryEval(*parse_call, R_GlobalEnv, &mut error_occurred);
            if error_occurred != 0 {
                return Err("Failed to parse test prelude");
            }
            let prelude_expr = RObj::protect(prelude_expr);

            let call = Rf_lang2(Rf_install("eval\0".as_ptr() as *const i8), *prelude_expr);
            let call = RObj::protect(call);
            let mut error_occurred = 0;
            R_tryEval(*call, R_GlobalEnv, &mut error_occurred);
            if error_occurred != 0 {
                return Err("Failed to run test prelude");
            }

            Rf_unprotect(5);
            Ok(())
        });

        drop(lock);

        *r
    }
}

fn call_r_file_test(input: &str, output: &str) {
    ensure_r_init().expect("Failed to initialize R");
    let lock = R_LOCK.lock().unwrap();

    unsafe {
        let input = Rf_mkCharCE(input.as_ptr() as *const i8, libR_sys::cetype_t::CE_UTF8);
        let input = Rf_ScalarString(input);
        let input = RObj::protect(input);

        let output = Rf_mkCharCE(output.as_ptr() as *const i8, libR_sys::cetype_t::CE_UTF8);
        let output = Rf_ScalarString(output);
        let output = RObj::protect(output);

        let call = Rf_lang3(
            Rf_install("do_file_test\0".as_ptr() as *const i8),
            *input,
            *output,
        );

        let call = RObj::protect(call);

        let mut error_occurred = 0;

        R_tryEval(*call, R_GlobalEnv, &mut error_occurred);

        if error_occurred != 0 {
            panic!("Failed to run test");
        }

        Rf_unprotect(3);
    }

    drop(lock);
}

fn call_r_string_test(mode: &str, input: &str) -> String {
    ensure_r_init().expect("Failed to initialize R");
    let lock = R_LOCK.lock().unwrap();

    unsafe {
        let input = Rf_mkCharLenCE(
            input.as_ptr() as *const i8,
            i32::try_from(input.len()).unwrap(),
            libR_sys::cetype_t::CE_BYTES,
        );
        let input = Rf_ScalarString(input);
        let input = RObj::protect(input);

        let mode = Rf_mkCharLenCE(
            mode.as_ptr() as *const i8,
            i32::try_from(mode.len()).unwrap(),
            libR_sys::cetype_t::CE_BYTES,
        );
        let mode = Rf_ScalarString(mode);
        let mode = RObj::protect(mode);

        let call = Rf_lang3(
            Rf_install("do_string_test\0".as_ptr() as *const i8),
            *mode,
            *input,
        );

        let call = RObj::protect(call);

        let mut error_occurred = 0;

        let out = RObj::protect(R_tryEval(*call, R_GlobalEnv, &mut error_occurred));

        if error_occurred != 0 {
            panic!("Failed to run test");
        }

        let out: String = out.try_into().expect("Failed to convert to string");

        let chksum = crc32_hex(out.as_bytes());

        Rf_unprotect(4);

        drop(lock);

        chksum
    }
}

#[test]
fn test_r_string_sort() {
    let test_file = get_test_file_gff3_gencode_mouse_m35();

    test_file.execute_test(current_func!(), |s| {
        let input_str = std::fs::read_to_string(s).unwrap();

        call_r_string_test("gff3", &input_str)
    });
}

#[test]
fn test_r_file_sort() {
    let test_file = get_test_file_gff3_gencode_mouse_m35();

    test_file.execute_test(current_func!(), |s| {
        let input = PathBuf::from(s);
        let tmp = TempFile::new(
            format!(
                "{}_r_{}.sorted",
                input.file_stem().unwrap().to_str().unwrap(),
                current_func!().replace(|c: char| !c.is_alphanumeric(), "_")
            )
            .as_str(),
            true,
        );

        call_r_file_test(s, tmp.as_path().to_str().unwrap());

        crc32_hex(File::open(&*tmp).unwrap())
    });
}
