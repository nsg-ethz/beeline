import { randomRequest, requestTo } from "./common.js";

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

export function setup() {
  requestTo(1);
  requestTo(2);
  requestTo(3);
  requestTo(4);
}

export default function() {
  randomRequest();
}