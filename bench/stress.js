import { randomRequest } from "./common.js";

export const options = {
  discardResponseBodies: true,
  executor: "ramping-arrival-rate",
  stages: [
    { duration: '1m', target: 200 },
    { duration: '2m', target: 200 }, 
    { duration: '1m', target: 0 }, 
  ],
};

export default function () {
  randomRequest();
}