import { randomRequest } from "./common.js";

const rate = __ENV.RATE || 10000;
const vus = __ENV.VUS || 3000;

export const options = {
  scenarios: {
    rps: {
      executor: "ramping-arrival-rate",
      stages: [
        { duration: "5s", target: rate },
        { duration: "55s", target: rate },
      ],
      preAllocatedVUs: vus,
    }
  }
};

export default randomRequest;