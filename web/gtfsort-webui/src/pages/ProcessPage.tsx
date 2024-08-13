import { AccessTime, Dangerous, Done, ErrorOutline, ExpandMore, HourglassBottom, Start, Warning } from "@mui/icons-material";
import {
    Accordion, AccordionDetails, AccordionSummary,
    Alert,
    Box, Button, Divider, FormControlLabel,
    FormGroup, Input, LinearProgress,
    LinearProgressProps, Paper, Typography
} from "@mui/material";
import { ChangeEvent, useEffect, useState } from "react";
import { useWorker, WorkerListener } from "../worker/gtfsort-worker-manager";
import { formatStopwatchTime, useStopwatch } from "../components/Stopwatch";
import { formatIssueForPanic, formatIssueForWeb, IssueLink } from "../components/issueLink";
import streamsaver from "streamsaver";


type State = {
    state: "ready" | "processing" | "done" | "error";
    input_file: ArrayBuffer | null;
    accordion_input_expanded: boolean;
    accordion_output_expanded: boolean
    next_job_id: number;
    size_sent?: number;
    size_written?: number;
    size_parsed?: number;
    size_total?: number;
    file_input_key: number;
    panicMsg: { message: string, stack?: string } | null;
    web_error?: any;
}

function job_id_to_name(job_id: number): string {
    return `job_${job_id}`;
}

function humanize_sizes<K extends string>(bytes: Record<K, number>): Record<K, string> {
    let max = 0;
    for (const key in bytes) {
        max = Math.max(max, bytes[key]);
    }

    const possible_units: [number, string][] = [[1, "B"], [1 << 10, "KB"], [1 << 20, "MB"], [1 << 30, "GB"]];

    const unit_to_use = possible_units.find(([unit, _]) => max < unit) || possible_units[possible_units.length - 1];

    let result: Partial<Record<K, string>> = {};

    for (const key in bytes) {
        result[key] = (bytes[key] / unit_to_use[0]).toFixed(2) + unit_to_use[1];
    }

    return result as Record<K, string>;
}

type JobInfoItem = {
    stream: WritableStream<Uint8Array>,
    writer: WritableStreamDefaultWriter<Uint8Array>,
    callback?: (job_info: JobInfoItem) => Promise<void>,
    start_time: number
}

let job_info: Record<string, JobInfoItem> = {};

function chunkArrayBuffer(input: ArrayBuffer, chunk_size: number, cb: (chunk: ArrayBuffer) => void) {
    const view = new DataView(input);
    const size = view.byteLength;
    let split = chunk_size;
    let last_split = 0;
    while (split < size) {
        while (view.getUint8(split) !== "\n".charCodeAt(0)) {
            split++;
        }
        cb(input.slice(last_split, Math.min(split + 1, size)));
        last_split = split + 1;
        split += chunk_size;
    }
    cb(input.slice(last_split, size));
}

function LinearProgressWithLabel(props: LinearProgressProps & { label: string | number, rlabel: string }) {
    return (
        <Box sx={{ display: 'flex', alignItems: 'center', paddingTop: "5px", paddingBottom: "5px" }}>
            <Box sx={{ width: '15%' }}>
                <Typography variant="body2" color="text.secondary">{typeof props.label === "string" ?
                    props.label
                    : `${Math.round(
                        props.label,
                    )}%`}</Typography>
            </Box>
            <Box sx={{ width: '70%', mr: 1 }}>
                <LinearProgress variant="determinate" {...props} />
            </Box>
            <Box sx={{ width: '15%' }}>
                <Typography variant="body2" color="text.secondary">{props.rlabel}</Typography>
            </Box>
        </Box>
    );
}

export default function ProcessPage() {
    const [state, setState] = useState<State>({
        state: "ready",
        input_file: null,
        accordion_input_expanded: true,
        accordion_output_expanded: true,
        next_job_id: 0,
        file_input_key: 0,
        panicMsg: null
    });

    const { sendMessage, addListener, removeListener } = useWorker();

    function isInputReady() {
        return !!state.input_file
    }

    const sw = useStopwatch();
    const sw_send = useStopwatch();
    const sw_parse = useStopwatch();
    const sw_write = useStopwatch();

    function reset() {
        if (state.state === "error") {
            window.location.reload();
            return;
        }
        [sw, sw_send, sw_parse, sw_write].forEach((s) => s.reset());
        sendMessage({ cmd: "clear_jobs" }, []);
        setState(({ file_input_key }) => ({
            state: "ready",
            input_text: "",
            input_file: null,
            accordion_input_expanded: true,
            accordion_output_expanded: true,
            next_job_id: 0,
            panicMsg: null,
            file_input_key: file_input_key + 1,
        }));
    }

    if (sw_send.state.status === "running" && state.size_sent === state.size_total) {
        sw_send.pause();
        sw_parse.start();
    }

    if (sw_parse.state.status === "running" && state.size_parsed === state.size_total) {
        sw_parse.pause();
        sw_write.start();
    }

    if (sw_write.state.status === "running" && state.size_written === state.size_total) {
        sw_write.pause();
    }

    if (state.web_error && state.state !== "error") {
        setState({ ...state, state: "error" });
    }

    useEffect(() => {
        const listener: WorkerListener = {
            onmessage: (data) => {
                switch (data.type) {
                    case "panic":
                        setState({ ...state, panicMsg: data, state: "error" });
                        break;
                    case "pipe_output":
                        const job_id = data.job_id;
                        const job = job_info[job_id];
                        if (job) {
                            setState((state) => {
                                return {
                                    ...state,
                                    size_written: (state.size_written || 0) + data.output.byteLength
                                }
                            });
                            job.writer.write(new Uint8Array(data.output));
                        }
                        break;
                    case "input_transferred":
                        setState((state) => {
                            return {
                                ...state,
                                size_sent: (state.size_sent || 0) + data.size
                            }
                        });
                        break;
                    case "input_parse_progress":
                        setState((state) => {
                            return {
                                ...state,
                                size_parsed: data.size,
                            }
                        });
                        break;
                    case "process_end":
                        [sw, sw_send, sw_parse, sw_write].forEach((s) => s.pause());
                        setState({ ...state, state: "done" });
                        const job_id_end = data.job_id;
                        const job_end = job_info[job_id_end];
                        if (job_end) {
                            job_end.writer.close().then(() => {
                                (job_end.callback?.(job_end) || Promise.resolve()).then(() => {
                                    [sw, sw_send, sw_parse, sw_write].forEach((s) => s.reset());
                                    delete job_info[job_id_end];
                                    setState({ ...state, state: "done", size_written: state.size_total });
                                }
                                ).catch((e) => {
                                    setState({ ...state, web_error: e });
                                });
                            });
                        }
                }
            }
        };

        addListener(listener);

        return () => {
            removeListener(listener);
        }
    });

    function submitJob(stream_factory: () => Promise<{
        stream: WritableStream<Uint8Array>,
        writer: WritableStreamDefaultWriter<Uint8Array>,
        callback?: (job_info: JobInfoItem) => Promise<void>
    }>): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            const job_id = job_id_to_name(state.next_job_id);
            setState({ ...state, next_job_id: state.next_job_id + 1, size_sent: 0, size_written: 0, state: "processing" });
            stream_factory().then(({ stream, writer, callback }) => {
                job_info[job_id] = { stream, writer, callback, start_time: Date.now() };

                if (state.input_file) {
                    sw.start();
                    sw_send.start();
                    sendMessage({
                        cmd: "declare_job",
                        job_id,
                        mode: "gff3",
                        output: {
                            type: "callback"
                        }
                    }, []);
                    chunkArrayBuffer(state.input_file, 1024 * 1024 * 64, (chunk) => {
                        sendMessage({
                            cmd: "pipe_input",
                            job_id,
                            input: chunk
                        }, [chunk]);
                    });
                    sendMessage({
                        cmd: "start_job",
                        job_id
                    }, []);
                    resolve();
                } else {
                    console.error("No input");
                    reject("No input");
                }
            }).catch((e) => {
                setState({ ...state, web_error: e, state: "error" });
                reject(e);
            });
        });
    }

    return (
        <div>
            <Typography variant="h3">Sort your GTF/GFF file here.</Typography>
            <Divider />
            {
                !window.Worker ?
                    <Typography variant="h6">Your browser does not support Web Workers. Please use a modern browser or download the binary.</Typography> :
                    <>
                        <Accordion
                            id="gtfsort-input-panel"
                            aria-controls="gtfsort-input-panel-content"
                            expanded={state.accordion_input_expanded}
                            onChange={() => setState({ ...state, accordion_input_expanded: !state.accordion_input_expanded })}
                        >
                            <AccordionSummary expandIcon={<ExpandMore />}>
                                {state.input_file ? <Done /> : <Warning />}
                                <Typography>Input
                                    <Typography variant="caption" sx={{ marginLeft: "1em" }}>
                                        {isInputReady() ? "Ready" : "Incomplete"}
                                    </Typography>
                                </Typography>
                            </AccordionSummary>
                            <AccordionDetails>
                                <FormGroup>
                                    <Typography variant="caption">
                                        All files are processed in the browser and never leave your computer.
                                    </Typography>
                                    <Button
                                        variant="contained"
                                        onClick={reset}
                                        color="error">
                                        {
                                            state.state === "error" ? "Reload Page" : "Start Over"
                                        }
                                    </Button>
                                    <Divider sx={{ marginBottom: "1em" }} />
                                    <FormControlLabel control={<Input
                                        key={state.file_input_key}
                                        type="file" onChange={async (e: ChangeEvent<HTMLInputElement>) => {
                                            const file = e.target.files?.[0];
                                            if (file) {
                                                const ab = await file.arrayBuffer();
                                                setState({ ...state, input_file: ab, size_total: ab.byteLength });
                                            }
                                        }} />} label="Select GTF/GFF file" labelPlacement="top" />
                                    <Divider sx={{ marginTop: "1em" }} />

                                    <Typography variant="h6">Summary</Typography>
                                    <Typography variant="caption">
                                        {
                                            state.size_total ?
                                                `Input Size: ${humanize_sizes({ size_total: state.size_total }).size_total}` :
                                                "No input"
                                        }
                                    </Typography>
                                </FormGroup>
                            </AccordionDetails>
                        </Accordion>
                        <Accordion
                            id="gtfsort-output-panel"
                            aria-controls="gtfsort-output-panel-content"
                            expanded={state.accordion_output_expanded}
                            onChange={() => setState({ ...state, accordion_output_expanded: !state.accordion_output_expanded })}
                        >
                            <AccordionSummary expandIcon={<ExpandMore />}>
                                {
                                    state.state === "error" ? <Dangerous /> :
                                        state.state === "processing" ? <HourglassBottom /> :
                                            state.state === "ready" ? (isInputReady() ? <Start /> : <AccessTime />) :
                                                state.state === "done" ? <Done /> :
                                                    <ErrorOutline />
                                }
                                <Typography>Execute
                                    <Typography variant="caption" sx={{ marginLeft: "1em" }}>
                                        {state.state === "processing" ? "In Progress" :
                                            state.state === "done" ? "Done" :
                                                state.state === "ready" ? (
                                                    isInputReady() ? "Ready" : "Waiting for configuration"
                                                ) : "Error"}
                                    </Typography>
                                </Typography>
                            </AccordionSummary>
                            <AccordionDetails>
                                <FormGroup>
                                    {
                                        (state.state === "error" || state.panicMsg) ?

                                            <Alert severity="error">
                                                {
                                                    state.panicMsg ?
                                                        `The GTFsort backend panicked: ${state.panicMsg.message || "Unknown Error"}`
                                                        : state.web_error ?
                                                            "An Web error occurred: " + state.web_error.message || "Unknown Error"
                                                            : "An unknown error occurred"
                                                }
                                                <Paper>
                                                    <Typography variant="caption">Technical Details</Typography>
                                                    <Typography variant="body2">
                                                        {
                                                            state.panicMsg?.stack?.split("\n").map((line, i) => {
                                                                return <span key={i}>{line}<br /></span>
                                                            }) || state.web_error?.stack?.split("\n").map((line: string, i: number) => {
                                                                return <span key={i}>{line}<br /></span>
                                                            }) || "No stack trace available"
                                                        }
                                                    </Typography>
                                                </Paper>
                                                {
                                                    state.panicMsg ? <IssueLink
                                                        repo="alejandrogzi/gtfsort"
                                                        {...formatIssueForPanic(state.panicMsg.stack, state.panicMsg.message)} /> :
                                                        state.web_error ? <IssueLink
                                                            repo="alejandrogzi/gtfsort"
                                                            {...formatIssueForWeb(state.web_error)}
                                                        /> : null
                                                }

                                            </Alert> : null
                                    }
                                    <Typography variant="h6">Progress</Typography>
                                    <Typography variant="caption">
                                        {
                                            sw.state.status === "running" ?
                                                `Elapsed Time: ${formatStopwatchTime(sw.state.elapsed)} +` :
                                                sw.state.status === "paused" ?
                                                    `Elapsed Time: ${formatStopwatchTime(sw.state.elapsed)} .` :
                                                    "Elapsed Time: N/A"
                                        }
                                    </Typography>
                                    {state.size_sent && state.size_total ?
                                        <LinearProgressWithLabel
                                            value={(state.size_sent / state.size_total) * 100}
                                            rlabel={sw_send.state.status === "running" ? `${formatStopwatchTime(sw_send.state.elapsed)} +` : sw_send.state.status === "paused" ? `${formatStopwatchTime(sw_send.state.elapsed)} .` : "N/A"}
                                            label={(() => {
                                                const sizes = humanize_sizes({
                                                    size_sent: state.size_sent,
                                                    size_total: state.size_total
                                                });
                                                return `${sizes.size_sent} / ${sizes.size_total} Sent`;
                                            })()} /> : <LinearProgressWithLabel value={0} label="Sending" rlabel="Pending" />
                                    }
                                    {state.size_parsed && state.size_total ?
                                        <LinearProgressWithLabel
                                            value={(state.size_parsed / state.size_total) * 100}
                                            rlabel={sw_parse.state.status === "running" ? `${formatStopwatchTime(sw_parse.state.elapsed)} +` : sw_parse.state.status === "paused" ? `${formatStopwatchTime(sw_parse.state.elapsed)} .` : "N/A"}
                                            label={(() => {
                                                const sizes = humanize_sizes({
                                                    size_parsed: state.size_parsed,
                                                    size_total: state.size_total
                                                });
                                                return `${sizes.size_parsed} / ${sizes.size_total} Parsed`;
                                            })()} /> :
                                        <LinearProgressWithLabel value={0} label="Processing" rlabel="Pending" />
                                    }
                                    {
                                        state.size_written && state.size_total ?
                                            <LinearProgressWithLabel
                                                value={(state.size_written / state.size_total) * 100}
                                                rlabel={sw_write.state.status === "running" ? `${formatStopwatchTime(sw_write.state.elapsed)} +` : sw_write.state.status === "paused" ? `${formatStopwatchTime(sw_write.state.elapsed)} .` : "N/A"}
                                                label={(() => {
                                                    const sizes = humanize_sizes({
                                                        size_written: state.size_written,
                                                        size_total: state.size_total
                                                    });
                                                    return `${sizes.size_written} / ${sizes.size_total} Written`;
                                                })()} /> : <LinearProgressWithLabel value={0} label="Writing" rlabel="Pending" />
                                    }
                                    <Divider sx={{ marginBottom: "1em" }} />
                                    <Typography variant="h6">Execute</Typography>
                                    <Button
                                        sx={{ marginTop: "2em" }}
                                        variant="contained"
                                        disabled={
                                            state.state !== "ready" ||
                                            !(window as any).showSaveFilePicker ||
                                            !isInputReady()}
                                        onClick={() =>
                                            submitJob(async () => {
                                                const handle: FileSystemFileHandle = await (window as any).showSaveFilePicker();
                                                const writable: FileSystemWritableFileStream = await handle.createWritable();
                                                return {
                                                    stream: writable,
                                                    writer: writable.getWriter(),
                                                };
                                            })
                                        }
                                    >
                                        {
                                            (window as any).showSaveFilePicker ?
                                                <Typography>Save Output</Typography> :
                                                <Typography>Save Output (Chrome/Edge/Opera Only)</Typography>
                                        }
                                    </Button>
                                    <Button
                                        sx={{ marginTop: "2em" }}
                                        disabled={state.state !== "ready" || !isInputReady()}
                                        variant="contained"
                                        onClick={() => {
                                            submitJob(async () => {
                                                const stream = streamsaver.createWriteStream("output.gff3");
                                                return {
                                                    stream,
                                                    writer: stream.getWriter()
                                                };
                                            });
                                        }}
                                    >
                                        Download Output
                                    </Button>
                                </FormGroup>
                            </AccordionDetails>
                        </Accordion>
                    </>
            }

        </div >
    );
}