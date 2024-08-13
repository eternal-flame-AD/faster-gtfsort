use std::{
    collections::HashMap,
    convert::TryFrom,
    env,
    io::{BufWriter, Write},
    sync::{atomic::AtomicUsize, RwLock},
};

use gtfsort::sort_annotations_string_sync;
use js_sys::{ArrayBuffer, DataView, Function, JsString};
use large_vec::ChunkedVec;
use wasm_bindgen::prelude::*;

mod large_vec;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    #[wasm_bindgen(js_namespace = console)]
    fn error(s: &str);
}

trait DataViewExt {
    fn get_array(&self, start: usize, end: usize) -> Vec<u8>;
}

impl DataViewExt for DataView {
    fn get_array(&self, start: usize, end: usize) -> Vec<u8> {
        let mut ret = Vec::new();
        for i in start..end {
            ret.push(self.get_uint8(i));
        }
        ret
    }
}

#[wasm_bindgen]
pub fn build_info() -> JsValue {
    let obj = js_sys::Object::new();

    js_sys::Reflect::set(
        &obj,
        &JsValue::from("name"),
        &JsValue::from(env!("CARGO_PKG_NAME")),
    )
    .expect("Failed to set name");

    js_sys::Reflect::set(
        &obj,
        &JsValue::from("version"),
        &JsValue::from(env!("CARGO_PKG_VERSION")),
    )
    .expect("Failed to set version");

    js_sys::Reflect::set(
        &obj,
        &JsValue::from("build_time"),
        &JsValue::from(env!("VERGEN_BUILD_TIMESTAMP")),
    )
    .expect("Failed to set build_time");

    js_sys::Reflect::set(
        &obj,
        &JsValue::from("git_describe"),
        &JsValue::from(env!("VERGEN_GIT_DESCRIBE")),
    )
    .expect("Failed to set git_describe");

    js_sys::Reflect::set(
        &obj,
        &JsValue::from("git_commit"),
        &JsValue::from(env!("VERGEN_GIT_SHA")),
    )
    .expect("Failed to set git_commit");

    obj.into()
}

enum Mode {
    Gtf,
    Gff,
}

impl TryFrom<&str> for Mode {
    type Error = ();
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value {
            "gtf" => Mode::Gtf,
            "gff" | "gff3" => Mode::Gff,
            _ => Err(())?,
        })
    }
}

pub struct JobContext {
    mode: Mode,
    input: ChunkedVec<u8>,
    dma_buffer: Vec<u8>,
}

static mut JOBS_PTR: Option<RwLock<HashMap<String, RwLock<JobContext>>>> = None;

macro_rules! get_jobs {
    () => {
        unsafe { JOBS_PTR.as_ref().unwrap() }
    };
}

struct CallbackWriter {
    callback: Function,
}

impl std::io::Write for CallbackWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let array_buffer = ArrayBuffer::new(buf.len() as u32);
        let view = DataView::new(&array_buffer, 0, buf.len());
        for (i, &v) in buf.iter().enumerate() {
            view.set_uint8(i, v);
        }

        match self.callback.call2(
            &JsValue::null(),
            &JsValue::from(buf.as_ptr() as u32),
            &buf.len().into(),
        ) {
            Ok(_) => Ok(buf.len()),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Callback error",
            )),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[wasm_bindgen]
pub fn clear_jobs() {
    let mut jobs = get_jobs!().write().unwrap();
    jobs.clear();
}

#[wasm_bindgen]
pub fn declare_job(name: &str, mode_str: &str) -> Result<JsValue, JsValue> {
    log(&format!("declare_job: {} {}", name, mode_str));
    let mut jobs = get_jobs!().write().unwrap();

    if jobs.contains_key(name) {
        return Err(JsString::from("Job already exists").into());
    }

    let mode = match Mode::try_from(mode_str) {
        Ok(m) => m,
        Err(_) => return Err(JsString::from("Unknown mode").into()),
    };

    jobs.insert(
        name.to_string(),
        RwLock::new(JobContext {
            mode,
            input: ChunkedVec::new(),
            dma_buffer: Vec::new(),
        }),
    );
    log(&format!(
        "jobs: {:?}",
        jobs.keys().cloned().collect::<Vec<_>>()
    ));
    Ok(JsValue::null())
}

#[wasm_bindgen]
pub fn pipe_input(name: &str, buffer: ArrayBuffer) -> Result<JsValue, JsValue> {
    log(&format!("pipe_input: {} {}", name, buffer.byte_length()));
    let jobs = get_jobs!().read().unwrap();
    log(&format!(
        "jobs: {:?}",
        jobs.keys().cloned().collect::<Vec<_>>()
    ));

    let job = match jobs.get(name) {
        Some(j) => j,
        None => return Err(JsString::from("Job not found").into()),
    };

    let view = DataView::new(&buffer, 0, buffer.byte_length() as usize);

    let chunk = view.get_array(0, buffer.byte_length() as usize);
    job.write().unwrap().input.push_chunk(chunk);

    Ok(JsValue::null())
}

#[wasm_bindgen]
pub fn start_dma_buffer(name: &str, size: usize) -> Result<JsValue, JsValue> {
    log(&format!("start_dma_buffer: {} {}", name, size));
    let jobs = get_jobs!().read().unwrap();

    let job = match jobs.get(name) {
        Some(j) => j,
        None => return Err(JsString::from("Job not found").into()),
    };

    let mut job = job.write().unwrap();
    job.dma_buffer = vec![0; size];

    Ok(JsValue::from(job.dma_buffer.as_ptr()))
}

#[wasm_bindgen]
pub fn commit_dma_buffer(name: &str) -> Result<JsValue, JsValue> {
    log(&format!("commit_dma_buffer: {}", name));
    let jobs = get_jobs!().read().unwrap();

    let job = match jobs.get(name) {
        Some(j) => j,
        None => return Err(JsString::from("Job not found").into()),
    };

    let mut job = job.write().unwrap();

    let mut copy = Vec::new();
    copy.extend_from_slice(&job.dma_buffer);

    job.input.push_chunk(copy);

    job.dma_buffer.clear();

    Ok(JsValue::null())
}

#[wasm_bindgen]
pub fn deliberate_panic() {
    panic!("Deliberate panic");
}

#[wasm_bindgen]
pub fn start_job(
    name: &str,
    progress_callback: Function,
    result_callback: Function,
    end_callback: Function,
) -> Result<JsValue, JsValue> {
    log(&format!("start_job: {}", name));
    let jobs = get_jobs!().read().unwrap();

    let job = match jobs.get(name) {
        Some(j) => j,
        None => return Err(JsString::from("Job not found").into()),
    };

    let job = job.read().unwrap();

    let mut io_err = None;

    let mut w = BufWriter::with_capacity(
        64 << 20,
        CallbackWriter {
            callback: result_callback,
        },
    );

    let total_size = job.input.iter_chunks().map(|r| r.len()).sum::<usize>();

    let last_reported_progress = AtomicUsize::new(0);
    let progress = AtomicUsize::new(0);
    let add_progress = |p: usize| {
        let cur = progress.fetch_add(p, std::sync::atomic::Ordering::Relaxed) + p;
        let last_reported = last_reported_progress.load(std::sync::atomic::Ordering::Relaxed);

        if cur - last_reported > total_size / 50 || cur == total_size {
            last_reported_progress.store(cur, std::sync::atomic::Ordering::Relaxed);
            progress_callback
                .call1(&JsValue::null(), &JsValue::from(cur))
                .unwrap();
        }
    };

    let result = match job.mode {
        Mode::Gtf => sort_annotations_string_sync::<b' ', _>(
            job.input.iter_chunks().flat_map(|r| {
                add_progress(r.len());
                r.split(|&c| c == b'\n' || c == b'\r')
                    .filter(|r| !r.is_empty())
                    .map(|r| unsafe { std::str::from_utf8_unchecked(r) })
            }),
            &mut |o| {
                w.write_all(o)
                    .map_err(|e| {
                        io_err = Some(e);
                        std::io::Error::new(std::io::ErrorKind::Other, "Callback error")
                    })
                    .map(|_| o.len())
            },
        ),
        Mode::Gff => sort_annotations_string_sync::<b'=', _>(
            job.input.iter_chunks().flat_map(|r| {
                add_progress(r.len());
                r.split(|&c| c == b'\n' || c == b'\r')
                    .filter(|r| !r.is_empty())
                    .map(|r| unsafe { std::str::from_utf8_unchecked(r) })
            }),
            &mut |o| {
                w.write_all(o)
                    .map_err(|e| {
                        io_err = Some(e);
                        std::io::Error::new(std::io::ErrorKind::Other, "Callback error")
                    })
                    .map(|_| o.len())
            },
        ),
    };

    w.flush()
        .map_err(|e| JsString::from(format!("Error flushing: {}", e)))?;
    drop(w);

    match result {
        Ok(r) => {
            log(&format!("Job done: {:?}", r));
            end_callback
                .call1(
                    &JsValue::null(),
                    &JsValue::from_f64(r.indexing_secs + r.parsing_secs + r.writing_secs),
                )
                .unwrap();
            Ok(JsValue::null())
        }
        Err(e) => Err(JsString::from(e.to_string()).into()),
    }
}

#[wasm_bindgen(start)]
pub fn main() {
    unsafe {
        JOBS_PTR = Some(RwLock::new(HashMap::new()));
    }
}
