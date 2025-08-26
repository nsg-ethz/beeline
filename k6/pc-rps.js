import { request } from "./common.js";

export const options = {
    scenarios: {
        rps: {
            executor: "ramping-arrival-rate",
            preAllocatedVUs: 1000,
            stages: [
                { target: 10000, duration: "10s" },
                { target: 10000, duration: "3m" },
            ],
            gracefulStop: "3s",
        },
    },
    discardResponseBodies: true,
};

export default request;
