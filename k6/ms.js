import { dest } from "./common.js";
import { check } from "k6";
import http from "k6/http";
import {
    randomString,
    randomIntBetween,
} from "https://jslib.k6.io/k6-utils/1.3.0/index.js";

const randomText = randomString(256);

export const options = {
    scenarios: {
        compose_review: {
            executor: "ramping-arrival-rate",
            preAllocatedVUs: 200,
            stages: [
                { target: 4000, duration: "100s" },
                { target: 4000, duration: "5s" },
            ],
            gracefulStop: "3s",
        },
    },
    discardResponseBodies: true,
};

export default () => {
    const userIndex = randomIntBetween(1, 1000);
    const movieIndex = randomIntBetween(1, 1000);
    const rating = randomIntBetween(0, 10);

    const body = `username=username_${userIndex}&password=password_${userIndex}&title=title_${movieIndex}&rating=${rating}&text=${randomText}`;
    const headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    };
    const params = {
        headers: headers,
        tags: { name: "compose" },
    };

    const res = http.post(`${dest}/wrk2-api/review/compose`, body, params);

    return check(res, {
        "status is 200": (r) => r.status === 200,
    });
};
