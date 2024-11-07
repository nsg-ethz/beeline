import { randomRequest } from "./common.js";

const rate = __ENV.RATE || 10000;
const vus = __ENV.VUS || 3000;

export const options = {
  scenarios: {
    rps: {
      executor: "constant-arrival-rate",
      duration: "1m",
      rate: rate,
      preAllocatedVUs: vus,
    }
  }
};

export default randomRequest;