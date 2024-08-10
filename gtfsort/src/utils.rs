use hashbrown::HashMap;
use itertools::Itertools;
use rayon::prelude::*;

use colored::Colorize;

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use indoc::indoc;
use log::info;

use crate::gtf::Record;
use crate::ord::NaturalSort;
use crate::SortAnnotationsJobResult;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub type Chrom<'a> = &'a str;
pub type ChromRecord<'a> = HashMap<Chrom<'a>, Vec<Record<'a>>>;

pub struct ChunkWriter<'f, F: FnMut(&[u8]) -> io::Result<usize>> {
    f: &'f mut F,
}

impl<'f, F: FnMut(&[u8]) -> io::Result<usize>> ChunkWriter<'f, F> {
    pub fn new(f: &'f mut F) -> Self {
        Self { f }
    }
}

impl<F> Write for ChunkWriter<'_, F>
where
    F: FnMut(&[u8]) -> io::Result<usize>,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (self.f)(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn timed<T, F: FnOnce() -> T>(key: &str, output: Option<&mut f64>, f: F) -> T {
    let start = std::time::Instant::now();
    let res = f();
    let elapsed = start.elapsed().as_secs_f64();
    if let Some(output) = output {
        *output = elapsed;
    }
    log::info!("{}: {:.2}s", key, elapsed);
    res
}

#[derive(Debug, Default)]
pub struct ChromTree<'a> {
    pub chrom: &'a str,
    pub genes: HashMap<&'a str, GeneTree<'a>>,
}

impl<'a> ChromTree<'a> {
    pub fn into_sorted(self) -> ChromTreeSorted<'a> {
        ChromTreeSorted {
            chrom: self.chrom,
            genes: self
                .genes
                .into_iter()
                .map(|(_, v)| v.into_sorted())
                .sorted_unstable_by_key(|x| (x.start_pos, x.end_pos))
                .collect_vec(),
        }
    }
}

#[derive(Debug, Default)]
pub struct ChromTreeSorted<'a> {
    pub chrom: &'a str,
    pub genes: Vec<GeneTreeSorted<'a>>,
}

impl<'a> ChromTreeSorted<'a> {
    pub fn count_line_size(&self) -> usize {
        self.genes.iter().map(|x| x.count_line_size()).sum()
    }
}

#[derive(Debug, Default)]
pub struct GeneTree<'a> {
    pub start_pos: u32,
    pub end_pos: u32,
    pub gene_id: &'a str,
    pub line: &'a str,
    pub transcripts: HashMap<&'a str, TranscriptTree<'a>>,
    pub original_transcript_order: Vec<&'a str>,
}

impl<'a> GeneTree<'a> {
    pub fn into_sorted(mut self) -> GeneTreeSorted<'a> {
        GeneTreeSorted {
            start_pos: self.start_pos,
            end_pos: self.end_pos,
            gene_id: self.gene_id,
            line: self.line,
            transcripts: self
                .original_transcript_order
                .into_iter()
                .map(|x| self.transcripts.remove(x).unwrap())
                .collect(),
        }
    }
}

#[derive(Debug, Default)]
pub struct GeneTreeSorted<'a> {
    pub start_pos: u32,
    pub end_pos: u32,
    pub gene_id: &'a str,
    pub line: &'a str,
    pub transcripts: Vec<TranscriptTree<'a>>,
}

#[derive(Debug, Default)]
pub struct TranscriptTree<'a> {
    pub transcript_id: &'a str,
    pub start_pos: u32,
    pub line: &'a str,
    pub inner_feats: BTreeMap<(i8, NaturalSort<&'a str>, char), Vec<&'a str>>,
}

impl<'a> ChromTree<'a> {
    pub fn push_record(&mut self, record: Record<'a>) {
        match record.feat {
            "gene" => {
                let r = self.genes.entry(record.gene_id).or_default();
                r.start_pos = record.start;
                r.end_pos = record.end;
                r.gene_id = record.gene_id;
                r.line = record.line;
            }
            "transcript" => {
                let r = self.genes.entry(record.gene_id).or_default();

                r.original_transcript_order.push(record.transcript_id);
                r.transcripts.insert(
                    record.transcript_id,
                    TranscriptTree {
                        transcript_id: record.transcript_id,
                        start_pos: record.start,
                        line: record.line,
                        inner_feats: BTreeMap::new(),
                    },
                );
            }
            "CDS" | "exon" | "start_codon" | "stop_codon" => {
                let (exon_number, suffix) = record.inner_layer();
                self.genes
                    .entry(record.gene_id)
                    .or_default()
                    .transcripts
                    .entry(record.transcript_id)
                    .or_default()
                    .inner_feats
                    .entry((0, NaturalSort(&exon_number), suffix))
                    .or_default()
                    .push(record.line);
            }
            _ => {
                self.genes
                    .entry(record.gene_id)
                    .or_default()
                    .transcripts
                    .entry(record.transcript_id)
                    .or_default()
                    .inner_feats
                    .entry((1, NaturalSort(record.feat), '\0'))
                    .or_default()
                    .push(record.line);
            }
        }
    }
}

impl<'a> GeneTreeSorted<'a> {
    pub fn count_line_size(&self) -> usize {
        let mut total = self.line.len() + 1;

        for tree in self.transcripts.iter() {
            total += tree.line.len() + 1;
            total += tree
                .inner_feats
                .values()
                .flatten()
                .map(|x| x.len() + 1)
                .sum::<usize>();
        }

        total
    }
}

#[cfg(not(feature = "mmap"))]
#[inline(always)]
pub fn write_obj<'a, P: AsRef<Path> + Debug>(
    file: P,
    obj: &DashMap<&'a str, Layers>,
    keys: Vec<(&'a str, usize)>,
    job: &mut Option<&mut SortAnnotationsJobResult>,
) -> Result<(), io::Error> {
    let f = match File::create(file) {
        Ok(f) => f,
        Err(e) => {
            log::error!("{} {}", "Error in output file:".bright_red().bold(), e);
            std::process::exit(1);
        }
    };

    write_obj_sequential(f, obj, keys, job)
}

#[cfg(feature = "mmap")]
#[inline(always)]
pub fn write_obj<'a, P: AsRef<Path> + Debug>(
    file: P,
    chroms: &[(&'a str, ChromTreeSorted<'a>)],
    job: &mut Option<&mut SortAnnotationsJobResult>,
) -> Result<(), io::Error> {
    write_obj_mmaped(&file, chroms, job).or_else(move |e| {
        log::warn!(
            "{} {}",
            "Error in mmaped output, falling back to sequential:"
                .bright_yellow()
                .bold(),
            e
        );

        let f = match File::create(file) {
            Ok(f) => f,
            Err(e) => {
                log::error!("{} {}", "Error in output file:".bright_red().bold(), e);
                std::process::exit(1);
            }
        };

        write_obj_sequential(f, chroms, job)
    })
}

pub fn write_obj_sequential<'a, W: Write>(
    file: W,
    chroms: &'a [(&'a str, ChromTreeSorted<'a>)],
    _job: &mut Option<&mut SortAnnotationsJobResult>,
) -> Result<(), io::Error> {
    use std::io::BufWriter;

    let mut output = BufWriter::new(file);

    chroms.iter().try_for_each(|(_, chr)| {
        chr.genes.iter().try_for_each(|gene| {
            writeln!(output, "{}", gene.line)?;

            gene.transcripts.iter().try_for_each(|transcript| {
                writeln!(output, "{}", transcript.line)?;

                transcript.inner_feats.iter().try_for_each(|(_, feats)| {
                    feats
                        .into_iter()
                        .try_for_each(|feat| writeln!(output, "{}", feat))
                })
            })
        })?;

        Ok::<_, io::Error>(())
    })?;

    output.flush()?;

    Ok(())
}

#[cfg(feature = "mmap")]
pub fn write_obj_mmaped<'a, P: AsRef<Path> + Debug>(
    file: P,
    chroms: &[(&'a str, ChromTreeSorted<'a>)],
    job: &mut Option<&mut SortAnnotationsJobResult>,
) -> Result<(), io::Error> {
    use std::{fs::OpenOptions, io::Cursor};

    use crate::mmap::{self, Madvice};

    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(file)?;

    let size = chroms
        .iter()
        .map(|(_, chr)| chr.count_line_size())
        .collect_vec();

    let total_size = size.iter().sum::<usize>();

    if total_size == 0 {
        return Ok(());
    }

    f.set_len(total_size as u64)?;

    #[cfg(unix)]
    let mut output_map = unsafe { mmap::MemoryMapMut::from_file(&f, total_size)? };

    #[cfg(windows)]
    let mut output_map = unsafe { mmap::MemoryMapMut::from_handle(&f, size as usize)? };

    match output_map.madvise(&[Madvice::Random]) {
        Ok(_) => (),
        Err(e) => {
            log::warn!("{} {}", "Madvice error:".bright_yellow().bold(), e);
        }
    }

    let mut output = output_map.as_mut_slice();

    log::info!(
        "Successfully mapped output file, size: {} bytes",
        output.len()
    );

    let mut output_slices = Vec::new();
    for s in size {
        let (a, b) = output.split_at_mut(s);
        output_slices.push(a);
        output = b;
    }

    chroms
        .into_iter()
        .zip(output_slices)
        .collect::<Vec<_>>()
        .into_par_iter()
        .try_for_each(|((_, chr), output)| {
            let size_expected = output.len();
            let mut output = Cursor::new(output);

            chr.genes.iter().try_for_each(|gene| {
                writeln!(output, "{}", gene.line)?;

                gene.transcripts.iter().try_for_each(|transcript| {
                    writeln!(output, "{}", transcript.line)?;

                    transcript.inner_feats.iter().try_for_each(|(_, feats)| {
                        feats
                            .into_iter()
                            .try_for_each(|feat| writeln!(output, "{}", feat))
                    })
                })
            })?;

            assert_eq!(
                output.position(),
                size_expected as u64,
                "Output buffer not empty, something went wrong"
            );

            Ok::<_, io::Error>(())
        })?;

    if let Some(j) = job.as_deref_mut() {
        j.output_mmaped = true;
    }

    output_map.close()?;

    Ok(())
}

pub fn parallel_parse<const SEP: u8>(s: &str) -> Result<ChromRecord<'_>, &'static str> {
    let x = s
        .par_lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| Record::parse::<SEP>(line).ok())
        .fold(HashMap::new, |mut acc: ChromRecord, record| {
            acc.entry(record.chrom).or_default().push(record);
            acc
        })
        .reduce(HashMap::new, |mut acc, map| {
            for (k, v) in map {
                acc.entry(k).or_default().extend(v);
            }
            acc
        });

    Ok(x)
}

#[cfg(not(windows))]
pub fn max_mem_usage_mb() -> f64 {
    let rusage = unsafe {
        let mut rusage = std::mem::MaybeUninit::uninit();
        if libc::getrusage(libc::RUSAGE_SELF, rusage.as_mut_ptr()) < 0 {
            info!("getrusage failed: {}", std::io::Error::last_os_error());
            return f64::NAN;
        }
        rusage.assume_init()
    };
    let maxrss = rusage.ru_maxrss as f64;
    if cfg!(target_os = "macos") {
        maxrss / 1024.0 / 1024.0
    } else {
        maxrss / 1024.0
    }
}

#[cfg(windows)]
pub fn max_mem_usage_mb() -> f64 {
    use windows::Win32::System::{
        ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
        Threading::GetCurrentProcess,
    };

    unsafe {
        let h_proc = GetCurrentProcess();

        let mut pps = PROCESS_MEMORY_COUNTERS::default();
        if GetProcessMemoryInfo(
            h_proc,
            &mut pps,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
        .is_err()
        {
            info!(
                "GetProcessMemoryInfo failed: {}",
                std::io::Error::last_os_error()
            );
            return f64::NAN;
        }

        pps.PeakWorkingSetSize as f64 / 1024.0 / 1024.0
    }
}

pub fn msg() {
    println!(
        "{}\n{}\n{}",
        "\n##### GTFSORT #####".bright_purple().bold(),
        indoc!(
            "The fastest chr/pos/feature GTF/GFF sorter you'll see.
        Repo: github.com/alejandrogzi/gtfsort
        Feel free to contact the developer if any issue/bug is found.
        "
        ),
        format!("Version: {}", VERSION)
    );
}
