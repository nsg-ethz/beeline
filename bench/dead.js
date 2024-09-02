import { randomRequest } from "./common.js";

export const options = {
  scenarios: {
    dead: {
      executor: "constant-arrival-rate",
      rate: 1,
      duration: "10m",
      preAllocatedVUs: 1000,
    }
  }
};

export default randomRequest;