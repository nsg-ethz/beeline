import { randomRequest } from "./common";

export const options = {
  discardResponseBodies: true,
  executor: "ramping-arrival-rate",
  stages: [
    { duration: "10m", target: 100000 }, 
  ],
};

export default function () {
  randomRequest();
}