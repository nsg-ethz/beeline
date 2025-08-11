import { request } from "./common.js";

const vus = __ENV.VUS || 3000;

export const options = {
    scenarios: {
        tput: {
            executor: "ramping-vus",
            startVUs: 0,
            stages: [
                { duration: "5s", target: vus },
                { duration: "60s", target: vus },
            ],
            gracefulRampDown: "3s",
        },
    },
};

export default request;
