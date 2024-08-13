
import { memory } from "../../gtfsort/pkg/gtfsort_web_bg.wasm";
import { build_info, clear_jobs, declare_job, start_job, main, start_dma_buffer, commit_dma_buffer, } from "../../gtfsort/pkg/gtfsort_web";

export type ProcessOutput = {
    type: "callback";
} | {
    type: "upload";
    url: string;
}

export type MessageInput = {
    cmd: "info";
} | {
    cmd: "declare_job";
    job_id: string;
    mode: "gff3" | "gff" | "gtf";
    output: ProcessOutput;
} | {
    cmd: "pipe_input";
    job_id: string;
    input: ArrayBuffer;
} | {
    cmd: "start_job";
    job_id: string;
} | {
    cmd: "clear_jobs";
}

export interface InfoOutput {
    version: string;
    build_date: string;
    build_time: string;
    git_describe: string;
    git_commit: string;
}

function errorHandler(e: any) {
    if (e instanceof WebAssembly.RuntimeError) {
        postMessage({
            type: "panic",
            message: e.message,
            stack: e.stack
        });
    }
}

export type MessageOutput =
    {
        type: "ready";
        info: InfoOutput;
    } | {
        type: "process_end";
        job_id: string;
        success: boolean;
    } | {
        type: "pipe_output";
        job_id: string;
        output: ArrayBuffer;
    } | {
        type: "input_transferred";
        job_id: string;
        size: number;
    } | {
        type: "input_parse_progress";
        job_id: string;
        size: number;
    } | {
        type: "panic";
        message: string;
        stack?: string;
    }



onmessage = async (e) => {
    await (async (e) => {
        const data = e.data as MessageInput;
        switch (data.cmd) {
            case "clear_jobs":
                clear_jobs();
                break;
            case "declare_job":
                declare_job(data.job_id, data.mode);
                break;
            case "pipe_input":
                const ptr = start_dma_buffer(data.job_id, data.input.byteLength);
                new Uint8ClampedArray(memory.buffer, ptr, data.input.byteLength).set(new Uint8Array(data.input));
                postMessage({
                    type: "input_transferred",
                    job_id: data.job_id,
                    size: data.input.byteLength
                });
                commit_dma_buffer(data.job_id);
                break;
            case "start_job":
                try {
                    start_job(data.job_id, (progress: number) => {
                        postMessage({
                            type: "input_parse_progress",
                            job_id: data.job_id,
                            size: progress
                        });
                    }, (ptr: number, len: number) => {
                        const buf = memory.buffer.slice(ptr, ptr + len);
                        postMessage({
                            type: "pipe_output",
                            job_id: data.job_id,
                            output: buf
                        }, { transfer: [buf] });
                    }, () => {
                        postMessage({
                            type: "process_end",
                            job_id: data.job_id,
                            success: true
                        });
                    });
                }
                catch (e) {
                    console.error(e);
                    postMessage({
                        type: "process_end",
                        job_id: data.job_id,
                        success: false
                    });
                }
                break;

            case "info":
                console.log(data);
                break;
        }
    })(e).catch(errorHandler);
};

try {
    main();
    postMessage({ type: "ready", info: build_info() });
} catch (e) {
    errorHandler(e);
}