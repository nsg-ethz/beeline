import http from "k6/http";

const vus = __ENV.VUS || 1000;

export const options = {
  scenarios: {
    tput: {
      executor: "constant-vus",
      duration: "60s",
      vus: vus,
    }
  }
};

export default function() {
  http.post("http://127.0.0.1:8000");
};