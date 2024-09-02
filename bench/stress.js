import { randomRequest } from "./common.js";

export const options = {
  scenarios: {
    stress: {
      executor: "constant-arrival-rate",
      rate: 10000,
      duration: "2m",
      preAllocatedVUs: 1000,
    }
  }
};

export default randomRequest;