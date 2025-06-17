import { generateWebToken } from "./common.js";
import { check } from "k6";
import exec from "k6/execution";
import http from "k6/http";
import {
    randomString,
    randomIntBetween,
} from "https://jslib.k6.io/k6-utils/1.3.0/index.js";

const randomText = randomString(256);
const randomUrl = randomString(64);

export const options = {
    scenarios: {
        compose_post: {
            executor: "ramping-arrival-rate",
            preAllocatedVUs: 300,
            stages: [
                { target: 4000, duration: "100s" },
                { target: 4000, duration: "5s" },
            ],
            gracefulStop: "3s",
        },
    },
    thresholds: {
        http_req_failed: [{ threshold: "rate<0.01" }],
    },
    discardResponseBodies: true,
};

function randomIntBetweenWithout(min, max, without) {
    while (true) {
        const val = randomIntBetween(min, max);
        if (val != without) return val;
    }
}

export default () => {
    const userIndex = randomIntBetween(0, 961);
    const userName = `username_${userIndex}`;
    const userId = userIndex.toString();
    const numUserMentions = randomIntBetween(0, 4);
    const numUrls = randomIntBetween(0, 4);
    const numMedia = randomIntBetween(0, 4);

    var text = randomText;
    for (let i = 0; i < numUserMentions; i++) {
        const userMentionId = randomIntBetweenWithout(0, 961, userIndex);
        text += ` @username_${userMentionId}`;
    }

    for (let i = 0; i < numUrls; i++) {
        text += ` http://${randomUrl}`;
    }

    var mediaIds = [];
    var mediaTypes = [];
    for (let i = 0; i < numMedia; i++) {
        mediaIds.push(`\"${randomIntBetween(0, 18)}\"`);
        mediaTypes.push('"png"');
    }

    const mediaIdsArg = `[${mediaIds.join(", ")}]`;
    const mediaTypesArg = `[${mediaTypes.join(", ")}]`;

    text += ` http://${randomUrl}/media/${randomString(32)}`;

    const id = exec.scenario.iterationInInstance.toString();
    const headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: "Bearer " + generateWebToken(id, true),
    };
    const params = {
        headers: headers,
        timeout: "3s",
    };

    var body;
    if (numMedia > 0) {
        body = `username=${userName}&user_id=${userId}&text=${text}&media_ids=${mediaIdsArg}&media_types=${mediaTypesArg}&post_type=0`;
    } else {
        body = `username=${userName}&user_id=${userId}&text=${text}&media_ids=${mediaIdsArg}&post_type=0`;
    }

    const res = http.post(
        "http://moonshine:8080/wrk2-api/post/compose",
        body,
        params,
    );

    return check(res, {
        "status is 200": (r) => r.status === 200,
    });
};
