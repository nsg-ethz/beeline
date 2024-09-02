import { requestTo } from "./common.js";

export const options = {
  scenarios: {
    stress: {
      executor: "ramping-vus",
      stages: [
        { duration: "10s", target: 3000 },
      ],
      gracefulStop: "0s"
    }
  }
};

export default function() {
  if (__ENV.BACKEND) {
    requestTo(__ENV.BACKEND);
  }
  else {
    requestTo(1);
    requestTo(2);
    requestTo(3);
    requestTo(4);
  }
}