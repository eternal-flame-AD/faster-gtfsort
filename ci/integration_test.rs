use std::{
    collections::VecDeque,
    fs::File,
    io::{BufRead, BufReader, Read},
    ops::Deref,
    path::{Path, PathBuf},
    sync::Once,
};

use flate2::read::GzDecoder;
use gtfsort::{sort_annotations, sort_annotations_string};
use log::Level;

// https://stackoverflow.com/a/40234666/9739737
macro_rules! current_func {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);
        name.strip_suffix("::f").unwrap()
    }};
}

pub struct TempFile {
    path: PathBuf,
    cleanup: bool,
}

impl TempFile {
    pub fn new(name: &str, cleanup: bool) -> Self {
        let path = std::env::temp_dir().join(name);
        Self { path, cleanup }
    }
}

impl Deref for TempFile {
    type Target = PathBuf;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.cleanup {
            std::fs::remove_file(&self.path).unwrap();
        }
    }
}

pub struct OnlyChromosomes<R> {
    inner: BufReader<R>,
    buf: Option<VecDeque<u8>>,
    chrom: &'static [&'static str],
}

impl<R: Read> OnlyChromosomes<R> {
    pub fn new(inner: R, chrom: &'static [&'static str]) -> Self {
        Self {
            inner: BufReader::new(inner),
            buf: None,
            chrom,
        }
    }
    pub fn buffer_more(&mut self) -> std::io::Result<usize> {
        let mut tot = 0;
        loop {
            let mut line = Vec::new();
            let n = self.inner.read_until(b'\n', &mut line)?;
            if n == 0 {
                return Ok(0);
            }
            tot += n;

            if line.starts_with(b"#")
                || self
                    .chrom
                    .iter()
                    .any(|&c| line.split(|c| *c == b'\t').next() == Some(c.as_bytes()))
            {
                let line = line.into_iter().collect::<VecDeque<_>>();
                self.buf = Some(line);
                return Ok(tot);
            }
        }
    }
}

impl<R: Read> Read for OnlyChromosomes<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.len() == 0 {
            return Ok(0);
        }

        if self.buf.is_none() {
            self.buffer_more()?;
        }

        let mut n = 0;
        while let Some(byte) = self.buf.as_mut().unwrap().pop_front() {
            buf[n] = byte;
            n += 1;
            if n == buf.len() {
                break;
            }
        }

        if n == 0 {
            if self.buffer_more()? == 0 {
                Ok(0)
            } else {
                self.read(buf)
            }
        } else {
            Ok(n)
        }
    }
}

const TEST_FILE_GFF3_GENCODE_MOUSE_M35_FILENAME: &str =
    "gencode.vM35.chr_patch_hapl_scaff.basic.annotation.gff3";
const TEST_FILE_GFF3_GENCODE_MOUSE_M35_URL: &str  = "https://ftp.ebi.ac.uk/pub/databases/gencode/Gencode_mouse/release_M35/gencode.vM35.chr_patch_hapl_scaff.basic.annotation.gff3.gz";
const TEST_FILE_GFF3_GENCODE_MOUSE_M35_TRANSFORMER: &dyn Fn(Box<dyn Read>) -> Box<dyn Read> =
    &|r| {
        Box::new(OnlyChromosomes::new(
            GzDecoder::new(r),
            &[
                "chr1",
                "chr2",
                "chr3",
                "chr5",
                "GL456221.1",
                "chrM",
                "ch11",
                "ch17",
            ],
        ))
    };
const TEST_FILE_GFF3_GENCODE_MOUSE_M35_EXPECT_OUTPUT_CKSUM: [&'static str; 1] = ["f6f3eb1d"];

fn crc32_hex<R: Read>(mut r: R) -> String {
    use crc::{Crc, CRC_32_CKSUM};

    let crc = Crc::<u32>::new(&CRC_32_CKSUM);
    let mut digest = crc.digest();

    let mut buffer = [0; 1024];

    loop {
        let n = r.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }

    format!("{:08x}", digest.finalize())
}

struct TestFile {
    name: String,
    expect_output_cksum: Vec<&'static str>,
}

impl TestFile {
    pub fn new_fs(name: &str, expect_output_cksum: &Vec<&'static str>) -> Self {
        Self {
            name: name.to_string(),
            expect_output_cksum: expect_output_cksum.clone(),
        }
    }
    pub fn from_url<RO: Read + ?Sized, F: Fn(Box<dyn Read>) -> Box<RO>>(
        cache_name: &str,
        url: &str,
        pipe: &F,
        expect_output_cksum: &Vec<&'static str>,
    ) -> Self {
        let tmpdir = std::env::temp_dir();

        let name = tmpdir.join(cache_name).to_string_lossy().to_string();
        let path = Path::new(&name);

        if path.exists() {
            return Self {
                name: path.to_str().unwrap().to_string(),
                expect_output_cksum: expect_output_cksum.clone(),
            };
        }

        let mut file = std::fs::File::create(&path).unwrap();

        let resp = reqwest::blocking::get(url).unwrap();

        std::io::copy(&mut pipe(Box::new(resp)), &mut file).unwrap();

        Self::new_fs(name.as_str(), expect_output_cksum)
    }
    pub fn execute_test<F: FnOnce(&str) -> String>(&self, name: &str, f: F) {
        let output_cksum = f(&self.name);

        if self.expect_output_cksum.is_empty() {
            eprintln!("{}: not comparing cksum, got: {}", name, output_cksum);
        } else {
            assert!(
                self.expect_output_cksum.contains(&output_cksum.as_str()),
                "{}: cksum mismatch, got: {}",
                name,
                output_cksum
            );
        }
    }
}

static INIT_LOGGER: Once = Once::new();

fn ensure_logger_initialized() {
    INIT_LOGGER.call_once(|| {
        simple_logger::init_with_level(Level::Info).unwrap();
    });
}

fn test_gencode_m35_subset_with_n_threads(nthreads: usize, prevent_mmap: bool) {
    static TEST_FILE_CELL: Once = Once::new();
    static mut TEST_FILE: Option<TestFile> = None;

    ensure_logger_initialized();

    TEST_FILE_CELL.call_once(|| unsafe {
        TEST_FILE = Some(TestFile::from_url(
            TEST_FILE_GFF3_GENCODE_MOUSE_M35_FILENAME,
            TEST_FILE_GFF3_GENCODE_MOUSE_M35_URL,
            &TEST_FILE_GFF3_GENCODE_MOUSE_M35_TRANSFORMER,
            &TEST_FILE_GFF3_GENCODE_MOUSE_M35_EXPECT_OUTPUT_CKSUM.to_vec(),
        ));
    });

    let test_file = unsafe { TEST_FILE.as_ref().unwrap() };

    if prevent_mmap {
        test_file.execute_test(current_func!(), |s| {
            let input_str = std::fs::read_to_string(s).unwrap();
            let mut output_buf = Vec::new();

            let job_info = sort_annotations_string::<b'=', _>(
                &input_str,
                &mut |b| {
                    output_buf.extend_from_slice(b);

                    Ok(b.len())
                },
                nthreads,
            )
            .expect("Failed to sort annotations");

            assert_eq!(job_info.threads, nthreads);

            assert_eq!(job_info.input_mmaped, false);
            assert_eq!(job_info.output_mmaped, false);

            assert!(job_info.end_mem_mb.unwrap().is_sign_positive());
            assert!(job_info.start_mem_mb.unwrap().is_sign_positive());

            crc32_hex(&output_buf[..])
        });
    } else {
        test_file.execute_test(current_func!(), |s| {
            let input = PathBuf::from(s);
            let tmp = TempFile::new(
                format!(
                    "{}_{}_{}.sorted",
                    input.file_stem().unwrap().to_str().unwrap(),
                    nthreads,
                    current_func!().replace(|c: char| !c.is_alphanumeric(), "_")
                )
                .as_str(),
                true,
            );

            let job_info =
                sort_annotations(&input, &tmp, nthreads).expect("Failed to sort annotations");

            assert_eq!(job_info.threads, nthreads);

            #[cfg(feature = "mmap")]
            {
                assert_eq!(job_info.input_mmaped, true);
                assert_eq!(job_info.output_mmaped, true);
            }
            #[cfg(not(feature = "mmap"))]
            {
                assert_eq!(job_info.input_mmaped, false);
                assert_eq!(job_info.output_mmaped, false);
            }

            assert!(job_info.end_mem_mb.unwrap().is_sign_positive());
            assert!(job_info.start_mem_mb.unwrap().is_sign_positive());

            crc32_hex(File::open(&*tmp).unwrap())
        });
    }
}

#[test]
fn test_gencode_m35_subset_single_thread() {
    test_gencode_m35_subset_with_n_threads(1, false);
}

#[test]
fn test_gencode_m35_subset_max_threads() {
    test_gencode_m35_subset_with_n_threads(num_cpus::get(), false);
}

#[test]
#[cfg(feature = "mmap")]
fn test_gencode_m35_subset_prevent_mmap_single_thread() {
    test_gencode_m35_subset_with_n_threads(1, true);
}

#[test]
#[cfg(feature = "mmap")]
fn test_gencode_m35_subset_prevent_mmap_max_threads() {
    test_gencode_m35_subset_with_n_threads(num_cpus::get(), true);
}
