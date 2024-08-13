import { useEffect, useState } from "react";
import gtfsortWorker from "../worker/gfsort-worker?worker";
import type { InfoOutput, MessageInput, MessageOutput } from "./gfsort-worker";

let worker: Worker | null = null;

export interface WorkerListener {
    onmessage?: (e: MessageOutput) => void;
}

let listeners: WorkerListener[] = [];

export type WorkerState = {
    status: "not ready"
}
    | {
        status: "ready",
        info: InfoOutput
    } | {
        status: "processing"
        info: InfoOutput
    }

export function useWorker() {
    const [state, setState] = useState<WorkerState>({
        status: "not ready"
    });

    const [forceUpdate, setForceUpdate] = useState(0);

    useEffect(() => {
        if (worker === null) {
            worker = new gtfsortWorker();
            worker.onmessage = (e) => {
                const data = e.data as MessageOutput;
                switch (data.type) {
                    case "ready":
                        setState({
                            status: "ready",
                            info: data.info
                        });
                        break;
                    case "process_end":
                        if (state.status === "processing") {
                            setState({
                                ...state,
                                status: "ready",
                            });
                        }
                        break;
                }
                listeners.forEach((l) => {
                    if (l.onmessage) {
                        l.onmessage(data);
                    }
                });
                setForceUpdate(forceUpdate + 1);
            }
        }
        return () => {
            if (worker !== null) {
                worker.terminate();
                worker = null;
            }
        }
    }, []);

    return {
        workerState: state,
        sendMessage: (msg: MessageInput, transfer: Transferable[]) => {
            if (worker !== null) {
                worker.postMessage(msg, transfer);
            }
        },
        addListener: (listener: WorkerListener) => {
            listeners.push(listener);
        },
        removeListener: (listener: WorkerListener) => {
            listeners = listeners.filter((l) => l !== listener);
        },
    }
}