import { useEffect, useState } from "react";

export type StopwatchState = {
    status: "ready",
} | {
    status: "running",
    start: number,
    elapsed: number
} | {
    status: "paused",
    start: number,
    elapsed: number
}

export function formatStopwatchTime(elapsed: number): string {
    const seconds = Math.floor(elapsed / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    return `${hours}:${minutes % 60}:${seconds % 60}.${Math.floor(elapsed % 1000 / 100)}`;
}

export function useStopwatch(): {
    state: StopwatchState,
    start: () => void,
    pause: () => void,
    reset: () => void
} {
    const [state, setState] = useState<StopwatchState>({
        status: "ready"
    });

    useEffect(() => {
        if (state.status === "running") {
            const interval = setInterval(() => {
                setState({
                    status: "running",
                    start: state.start,
                    elapsed: Date.now() - state.start
                });
            }, 100);
            return () => {
                clearInterval(interval);
            }
        }
    }, [state.status]);

    const start = () => {
        setState({
            status: "running",
            start: Date.now(),
            elapsed: 0
        });
    }

    const pause = () => {
        if (state.status === "running") {
            setState({
                status: "paused",
                start: state.start,
                elapsed: Date.now() - state.start
            });
        }
    }

    const reset = () => {
        setState({
            status: "ready"
        });
    }

    return {
        state,
        start,
        pause,
        reset,
    }
}