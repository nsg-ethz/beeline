import { randomRequest } from "./common.js";

export const options = {
  scenarios: {
    randomRequests: {
      executor: "constant-arrival-rate",
      rate: 5000,
      duration: "2m",
      preAllocatedVUs: 10000,
    }
  }
};

export default function () {
  randomRequest();
}