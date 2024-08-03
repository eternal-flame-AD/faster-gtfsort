#[cfg(feature = "c_ffi")]
pub mod c_ffi {
    use crate::{GtfSortError, SortAnnotationsJobResult};

    use std::ffi::{c_char, c_ulong, c_void, CStr, CString};

    #[repr(C)]
    pub struct GtfSortErrorFFI {
        pub code: i32,
        pub message: *const c_char,
    }

    pub const GTFSORT_ERROR_INVALID_INPUT: i32 = 1;
    pub const GTFSORT_ERROR_INVALID_OUTPUT: i32 = 2;
    pub const GTFSORT_ERROR_PARSE_ERROR: i32 = 3;
    pub const GTFSORT_ERROR_INVALID_THREADS: i32 = 4;
    pub const GTFSORT_ERROR_IO_ERROR: i32 = 5;
    pub const GTFSORT_ERROR_INVALID_PARAMETER: i32 = -1;

    macro_rules! cstr {
        ($s:expr) => {
            CString::new($s).unwrap().into_raw()
        };
    }

    macro_rules! cstr_free {
        ($s:expr) => {
            if !$s.is_null() {
                drop(CString::from_raw($s as *mut _));
            }
        };
    }

    impl From<GtfSortError> for GtfSortErrorFFI {
        fn from(e: GtfSortError) -> Self {
            match e {
                GtfSortError::InvalidInput(s) => Self {
                    code: GTFSORT_ERROR_INVALID_INPUT,
                    message: cstr!(s),
                },
                GtfSortError::InvalidOutput(s) => Self {
                    code: GTFSORT_ERROR_INVALID_OUTPUT,
                    message: cstr!(s),
                },
                GtfSortError::ParseError(s) => Self {
                    code: GTFSORT_ERROR_PARSE_ERROR,
                    message: cstr!(s),
                },
                GtfSortError::InvalidThreads(s) => Self {
                    code: GTFSORT_ERROR_INVALID_THREADS,
                    message: cstr!(s),
                },
                GtfSortError::IoError(s, e) => Self {
                    code: GTFSORT_ERROR_IO_ERROR,
                    message: cstr!(format!("{}: {}", s, e)),
                },
                GtfSortError::InvalidParameter(s) => Self {
                    code: GTFSORT_ERROR_INVALID_PARAMETER,
                    message: cstr!(s),
                },
            }
        }
    }

    #[repr(C)]
    pub struct SortAnnotationsJobResultFFI {
        pub input: *const c_char,
        pub output: *const c_char,
        pub threads: usize,
        pub input_mmaped: bool,
        pub output_mmaped: bool,
        pub parsing_secs: f64,
        pub indexing_secs: f64,
        pub writing_secs: f64,
        pub start_mem_mb: f64,
        pub end_mem_mb: f64,
    }

    impl From<SortAnnotationsJobResult<'_>> for SortAnnotationsJobResultFFI {
        fn from(r: SortAnnotationsJobResult) -> Self {
            Self {
                input: cstr!(r.input),
                output: cstr!(r.output),
                threads: r.threads,
                input_mmaped: r.input_mmaped,
                output_mmaped: r.output_mmaped,
                parsing_secs: r.parsing_secs,
                indexing_secs: r.indexing_secs,
                writing_secs: r.writing_secs,
                start_mem_mb: r.start_mem_mb.unwrap_or(f64::NAN),
                end_mem_mb: r.end_mem_mb.unwrap_or(f64::NAN),
            }
        }
    }

    #[repr(C)]
    pub enum SortAnnotationsRet {
        Ok(*mut SortAnnotationsJobResultFFI),
        Err(*mut GtfSortErrorFFI),
    }

    const GTFSORT_PARSE_MODE_GTF: u8 = 1;
    const GTFSORT_PARSE_MODE_GFF3: u8 = 2;

    #[no_mangle]
    unsafe extern "C" fn gtfsort_init_logger(level: *const c_char) {
        let level = unsafe { CStr::from_ptr(level).to_str().unwrap_or("info") };
        match level.to_ascii_lowercase().as_str() {
            "trace" => simple_logger::init_with_level(log::Level::Trace).unwrap(),
            "debug" => simple_logger::init_with_level(log::Level::Debug).unwrap(),
            "info" => simple_logger::init_with_level(log::Level::Info).unwrap(),
            "warn" => simple_logger::init_with_level(log::Level::Warn).unwrap(),
            "error" => simple_logger::init_with_level(log::Level::Error).unwrap(),
            _ => simple_logger::init_with_level(log::Level::Info).unwrap(),
        }
    }

    #[no_mangle]
    unsafe extern "C" fn gtfsort_new_sort_annotations_ret() -> *mut SortAnnotationsRet {
        Box::into_raw(Box::new(SortAnnotationsRet::Ok(std::ptr::null_mut())))
    }

    #[no_mangle]
    unsafe extern "C" fn gtfsort_free_sort_annotations_ret(ret: SortAnnotationsRet) {
        match ret {
            SortAnnotationsRet::Ok(ptr) => unsafe {
                cstr_free!((*ptr).input);
                cstr_free!((*ptr).output);
                drop(Box::from_raw(ptr));
            },
            SortAnnotationsRet::Err(ptr) => unsafe {
                cstr_free!((*ptr).message);
                drop(Box::from_raw(ptr));
            },
        }
    }

    #[no_mangle]
    unsafe extern "C" fn gtfsort_sort_annotations(
        input: *const std::os::raw::c_char,
        output: *const std::os::raw::c_char,
        threads: usize,
        result_ptr: *mut SortAnnotationsRet,
    ) -> bool {
        let input = std::path::PathBuf::from(unsafe { CStr::from_ptr(input).to_str().unwrap() });
        let output = std::path::PathBuf::from(unsafe { CStr::from_ptr(output).to_str().unwrap() });

        let result = crate::sort_annotations(&input, &output, threads);

        let ok = result.is_ok();

        if !result_ptr.is_null() {
            unsafe {
                *result_ptr = match result {
                    Ok(r) => SortAnnotationsRet::Ok(Box::into_raw(Box::new(r.into()))),
                    Err(e) => SortAnnotationsRet::Err(Box::into_raw(Box::new(e.into()))),
                };
            }
        }

        ok
    }

    #[no_mangle]
    unsafe extern "C" fn gtfsort_sort_annotations_gtf_str(
        mode: u8,
        input: *const c_char,
        output: extern "C" fn(*mut c_void, *const c_char, c_ulong) -> *const c_char,
        threads: usize,
        caller_data: *mut c_void,
        result_ptr: *mut SortAnnotationsRet,
    ) -> bool {
        let input = unsafe { CStr::from_ptr(input).to_str().unwrap() };

        let mut output = |str: &[u8]| {
            let ret = output(
                caller_data,
                unsafe { CStr::from_bytes_with_nul_unchecked(str).as_ptr() },
                str.len() as c_ulong,
            );
            match ret.is_null() {
                true => Ok(str.len()),
                false => Err(std::io::Error::other(unsafe {
                    CStr::from_ptr(ret).to_str().unwrap()
                })),
            }
        };

        let result = match mode {
            GTFSORT_PARSE_MODE_GTF => {
                crate::sort_annotations_string::<b' ', _>(input, &mut output, threads)
            }
            GTFSORT_PARSE_MODE_GFF3 => {
                crate::sort_annotations_string::<b'=', _>(input, &mut output, threads)
            }
            _ => {
                unsafe {
                    *result_ptr = SortAnnotationsRet::Err(Box::into_raw(Box::new(
                        GtfSortError::InvalidParameter("invalid parse mode").into(),
                    )));
                }
                return false;
            }
        };

        let ok = result.is_ok();

        if !result_ptr.is_null() {
            unsafe {
                *result_ptr = match result {
                    Ok(r) => SortAnnotationsRet::Ok(Box::into_raw(Box::new(r.into()))),
                    Err(e) => SortAnnotationsRet::Err(Box::into_raw(Box::new(e.into()))),
                };
            }
        }

        ok
    }
}

#[cfg(feature = "r_ffi")]
pub mod r_ffi {
    use std::{
        ffi::{c_char, CString},
        mem::transmute,
        ops::Deref,
        path::PathBuf,
        ptr::{self, addr_of},
    };

    use log::{info, Level, Log};

    use libR_sys::{
        DllInfo, R_CallMethodDef, R_GlobalEnv, R_registerRoutines, R_tryEval, R_useDynamicSymbols,
        Rboolean, Rf_ScalarInteger, Rf_ScalarLogical, Rf_ScalarReal, Rf_ScalarString,
        Rf_allocVector, Rf_asChar, Rf_install, Rf_lang3, Rf_mkCharLenCE, Rf_mkNamed, Rf_mkString,
        Rf_protect, Rf_translateCharUTF8, Rf_unprotect, Rf_warning, Rprintf, CDR, SET_STRING_ELT,
        SET_VECTOR_ELT, SEXP, SEXPTYPE,
    };

    use crate::{GtfSortError, SortAnnotationsJobResult};

    #[repr(transparent)]
    #[derive(Debug, Clone, Copy)]
    pub struct RObj(pub SEXP);

    impl RObj {
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub fn protect(sexp: SEXP) -> Self {
            unsafe { RObj(Rf_protect(sexp)) }
        }
    }

    impl Deref for RObj {
        type Target = SEXP;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl RObj {
        fn clos_call1(&self, arg: RObj) -> Result<RObj, ()> {
            unsafe {
                let list = Rf_protect(Rf_allocVector(SEXPTYPE::VECSXP, 1));

                SET_VECTOR_ELT(list, 0, *arg);

                let call = Rf_protect(Rf_lang3(
                    Rf_install("do.call\0".as_ptr() as *const c_char),
                    **self,
                    list,
                ));

                let mut error_occurred = 0;

                let ret = R_tryEval(call, R_GlobalEnv, &mut error_occurred);

                Rf_unprotect(2);

                if error_occurred != 0 {
                    Err(())
                } else {
                    Ok(RObj(ret))
                }
            }
        }
    }

    #[allow(clippy::from_over_into)]
    impl Into<bool> for RObj {
        fn into(self) -> bool {
            unsafe { libR_sys::Rf_asLogical(self.0) != 0 }
        }
    }

    #[allow(clippy::from_over_into)]
    impl Into<usize> for RObj {
        fn into(self) -> usize {
            unsafe { libR_sys::Rf_asInteger(self.0) as usize }
        }
    }

    impl TryInto<String> for RObj {
        type Error = Box<dyn std::error::Error>;

        fn try_into(self) -> Result<String, Self::Error> {
            let r_string = unsafe { Rf_asChar(self.0) };
            let c_string = unsafe { Rf_translateCharUTF8(r_string) };
            let rust_string = unsafe { std::ffi::CStr::from_ptr(c_string).to_str()?.to_owned() };
            Ok(rust_string)
        }
    }

    impl From<&str> for RObj {
        fn from(s: &str) -> Self {
            unsafe {
                let s = CString::new(s).unwrap();
                let s = Rf_protect(Rf_mkString(s.as_ptr()));

                Rf_unprotect(1);

                Self(s)
            }
        }
    }

    impl From<&[&str]> for RObj {
        fn from(s: &[&str]) -> Self {
            unsafe {
                let mut ret = Rf_protect(Rf_allocVector(SEXPTYPE::STRSXP, s.len() as isize));

                for (i, x) in s.iter().enumerate() {
                    let x = CString::new(*x).unwrap();
                    let x = Rf_protect(Rf_mkString(x.as_ptr()));
                    SET_STRING_ELT(ret, i as isize, x);
                    ret = CDR(ret);
                }

                Rf_unprotect(s.len() as i32 + 1);

                Self(ret)
            }
        }
    }

    impl From<GtfSortError> for RObj {
        fn from(e: GtfSortError) -> Self {
            unsafe {
                let mut ret = vec![("success", Rf_protect(Rf_ScalarLogical(0)))];
                let mut prot_count = 1;

                match e {
                    GtfSortError::InvalidInput(s) => {
                        ret.push((
                            "type",
                            Rf_protect(Rf_mkString("invalid_input\0".as_ptr() as *const c_char)),
                        ));
                        ret.push(("error", Rf_protect(RObj::from(s.as_str()).0)));
                        prot_count += 2;
                    }
                    GtfSortError::InvalidOutput(s) => {
                        ret.push((
                            "type",
                            Rf_protect(Rf_mkString("invalid_output\0".as_ptr() as *const c_char)),
                        ));
                        ret.push(("error", Rf_protect(RObj::from(s.as_str()).0)));
                        prot_count += 2;
                    }
                    GtfSortError::ParseError(s) => {
                        ret.push((
                            "type",
                            Rf_protect(Rf_mkString("parse_error\0".as_ptr() as *const c_char)),
                        ));
                        ret.push(("error", Rf_protect(RObj::from(s).0)));
                        prot_count += 2;
                    }
                    GtfSortError::InvalidThreads(s) => {
                        ret.push((
                            "type",
                            Rf_protect(Rf_mkString("invalid_threads\0".as_ptr() as *const c_char)),
                        ));
                        ret.push(("error", Rf_protect(RObj::from(s.as_str()).0)));
                        prot_count += 2;
                    }
                    GtfSortError::IoError(s, e) => {
                        ret.push((
                            "type",
                            Rf_protect(Rf_mkString("io_error\0".as_ptr() as *const c_char)),
                        ));
                        ret.push((
                            "error",
                            Rf_protect(RObj::from(format!("{}: {}", s, e).as_str()).0),
                        ));
                        prot_count += 2;
                    }
                    GtfSortError::InvalidParameter(s) => {
                        ret.push((
                            "type",
                            Rf_protect(
                                Rf_mkString("invalid_parameter\0".as_ptr() as *const c_char),
                            ),
                        ));
                        ret.push(("error", Rf_protect(RObj::from(s).0)));
                        prot_count += 2;
                    }
                }

                let ret = Rf_protect(make_named_list(&ret));
                Rf_unprotect(prot_count + 1);

                Self(ret)
            }
        }
    }

    impl From<SortAnnotationsJobResult<'_>> for RObj {
        fn from(r: SortAnnotationsJobResult) -> Self {
            unsafe {
                let mut prot_count = 1;
                let mut ret = vec![("success", Rf_protect(Rf_ScalarLogical(1)))];

                ret.push(("threads", Rf_protect(Rf_ScalarInteger(r.threads as i32))));
                prot_count += 1;

                ret.push((
                    "input_mmaped",
                    Rf_protect(Rf_ScalarLogical(r.input_mmaped as i32)),
                ));
                prot_count += 1;

                ret.push((
                    "output_mmaped",
                    Rf_protect(Rf_ScalarLogical(r.output_mmaped as i32)),
                ));
                prot_count += 1;

                ret.push(("parsing_secs", Rf_protect(Rf_ScalarReal(r.parsing_secs))));
                prot_count += 1;

                ret.push(("indexing_secs", Rf_protect(Rf_ScalarReal(r.indexing_secs))));
                prot_count += 1;

                ret.push(("writing_secs", Rf_protect(Rf_ScalarReal(r.writing_secs))));
                prot_count += 1;

                if let Some(start_mem_mb) = r.start_mem_mb {
                    ret.push(("start_mem_mb", Rf_protect(Rf_ScalarReal(start_mem_mb))));
                    prot_count += 1;
                }

                if let Some(end_mem_mb) = r.end_mem_mb {
                    ret.push(("end_mem_mb", Rf_protect(Rf_ScalarReal(end_mem_mb))));
                    prot_count += 1;
                }

                let ret = Rf_protect(make_named_list(&ret));

                Rf_unprotect(prot_count + 1);

                Self(ret)
            }
        }
    }

    struct RLogger {
        max_level: Level,
    }

    impl RLogger {
        const fn new() -> Self {
            Self {
                max_level: Level::Info,
            }
        }

        fn set_max_level(&mut self, max_level: Level) {
            self.max_level = max_level;
        }
    }

    impl Log for RLogger {
        fn enabled(&self, metadata: &log::Metadata) -> bool {
            metadata.level() <= self.max_level
        }

        fn log(&self, record: &log::Record) {
            if self.enabled(record.metadata()) {
                let level = record.level();

                let msg = format!("[{}] [{}] {}", level, record.target(), record.args());
                let msg_c = CString::new(msg).expect("Failed to convert message to CString.");

                unsafe {
                    match level {
                        Level::Warn => {
                            let fmtstr = "%s";
                            let fmtstr_c = CString::new(fmtstr)
                                .expect("Failed to convert message to CString.");
                            Rf_warning(fmtstr_c.as_ptr(), msg_c.as_ptr())
                        }
                        _ => {
                            let fmtstr = "%s\n";
                            let fmtstr_c = CString::new(fmtstr)
                                .expect("Failed to convert message to CString.");
                            Rprintf(fmtstr_c.as_ptr(), msg_c.as_ptr());
                        }
                    }
                }
            }
        }

        fn flush(&self) {}
    }

    static mut R_LOGGER: RLogger = RLogger::new();

    fn make_named_list(input: &[(&str, SEXP)]) -> SEXP {
        unsafe {
            let values = input.iter().map(|(_, value)| *value).collect::<Vec<_>>();

            let mut names_c = input
                .iter()
                .map(|(name, _)| CString::new(*name).unwrap())
                .collect::<Vec<_>>();

            let mut names_c_ptrs = names_c
                .iter_mut()
                .map(|name| name.as_ptr())
                .collect::<Vec<_>>();

            names_c_ptrs.push("\0".as_ptr() as *const c_char);

            let list = Rf_protect(Rf_mkNamed(SEXPTYPE::VECSXP, names_c_ptrs.as_mut_ptr()));

            values.iter().enumerate().for_each(|(i, value)| {
                SET_VECTOR_ELT(list, i as isize, *value);
            });

            Rf_unprotect(1);

            list
        }
    }

    #[export_name = "R_init_libgtfsort"]
    #[no_mangle]
    unsafe extern "C" fn R_init(dllinfo: *mut DllInfo) {
        unsafe {
            log::set_logger(&*addr_of!(R_LOGGER)).unwrap();
        }

        #[allow(clippy::missing_transmute_annotations)]
        let call_routines = [
            R_CallMethodDef {
                name: "gtfsort_init_logger\0".as_ptr() as *const c_char,
                fun: Some(unsafe {
                    transmute(gtfsort_R_init_logger as unsafe extern "C" fn(RObj) -> SEXP)
                }),
                numArgs: 1,
            },
            R_CallMethodDef {
                name: "gtfsort_sort_annotations\0".as_ptr() as *const c_char,
                fun: Some(unsafe {
                    transmute(
                        gtfsort_R_sort_annotations
                            as unsafe extern "C" fn(RObj, RObj, RObj) -> SEXP,
                    )
                }),
                numArgs: 3,
            },
            R_CallMethodDef {
                name: "gtfsort_sort_annotations_string\0".as_ptr() as *const c_char,
                fun: Some(unsafe {
                    transmute(
                        gtfsort_R_sort_annotations_string
                            as unsafe extern "C" fn(RObj, RObj, RObj, RObj) -> SEXP,
                    )
                }),
                numArgs: 4,
            },
            R_CallMethodDef {
                name: ptr::null(),
                fun: None,
                numArgs: 0,
            },
        ];

        unsafe {
            R_registerRoutines(
                dllinfo,
                ptr::null(),
                call_routines.as_ptr(),
                ptr::null(),
                ptr::null(),
            );

            R_useDynamicSymbols(dllinfo, Rboolean::FALSE);
        }

        info!("gtfsort initialized");
    }

    #[export_name = "gtfsort_R_init_logger"]
    #[no_mangle]
    pub extern "C" fn gtfsort_R_init_logger(level: RObj) -> SEXP {
        let level: String = level
            .try_into()
            .expect("Failed to convert level to string.");

        let l = level.to_ascii_lowercase();
        let mut l = l.as_str();

        match level.to_ascii_lowercase().as_str() {
            "trace" => unsafe { R_LOGGER.set_max_level(Level::Trace) },
            "debug" => unsafe { R_LOGGER.set_max_level(Level::Debug) },
            "info" => unsafe { R_LOGGER.set_max_level(Level::Info) },
            "warn" => unsafe { R_LOGGER.set_max_level(Level::Warn) },
            "error" => unsafe { R_LOGGER.set_max_level(Level::Error) },
            _ => unsafe {
                R_LOGGER.set_max_level(Level::Info);
                l = "info";
            },
        }

        unsafe { make_named_list(&[("success", Rf_ScalarLogical(1)), ("level", RObj::from(l).0)]) }
    }

    #[export_name = "gtfsort_R_sort_annotations"]
    #[no_mangle]
    pub extern "C" fn gtfsort_R_sort_annotations(input: RObj, output: RObj, threads: RObj) -> SEXP {
        let input: String = input
            .try_into()
            .expect("Failed to convert input to string.");
        let input = PathBuf::from(input);
        let output: String = output
            .try_into()
            .expect("Failed to convert output to string.");
        let output = PathBuf::from(output);
        let threads = threads.into();

        log::info!("Sorting annotations from {:?} to {:?}", input, output);

        let result = crate::sort_annotations(&input, &output, threads);
        match result {
            Ok(r) => RObj::from(r).0,
            Err(e) => RObj::from(e).0,
        }
    }

    #[export_name = "gtfsort_R_sort_annotations_string"]
    #[no_mangle]
    pub extern "C" fn gtfsort_R_sort_annotations_string(
        mode: RObj,
        input: RObj,
        output: RObj,
        threads: RObj,
    ) -> SEXP {
        let mode: String = mode.try_into().expect("Failed to convert mode to string.");
        let input: String = input
            .try_into()
            .expect("Failed to convert input to string.");
        let threads = threads.into();

        let mut output = |str: &[u8]| {
            let ret = output.clos_call1(RObj::protect(unsafe {
                Rf_ScalarString(Rf_mkCharLenCE(
                    str.as_ptr() as *const i8,
                    str.len() as i32,
                    libR_sys::cetype_t::CE_BYTES,
                ))
            }));
            unsafe {
                Rf_unprotect(1);
            }
            match ret {
                Ok(_) => Ok(str.len()),
                Err(_) => Err(std::io::Error::new(std::io::ErrorKind::Other, "R error")),
            }
        };

        let result = match mode.as_str() {
            "gtf" => crate::sort_annotations_string::<b' ', _>(&input, &mut output, threads),
            "gff" | "gff3" => {
                crate::sort_annotations_string::<b'=', _>(&input, &mut output, threads)
            }
            _ => Err(crate::GtfSortError::InvalidParameter("invalid parse mode")),
        };

        match result {
            Ok(r) => RObj::from(r).0,
            Err(e) => RObj::from(e).0,
        }
    }
}
