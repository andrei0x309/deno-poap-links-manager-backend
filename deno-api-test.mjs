import fetch from "node-fetch";
import dotenv from "dotenv";
const ENV = dotenv.config();

const endpointUrl = ENV.parsed.ENDPOINT;

const PRESHARED_AUTH_HEADER_KEY = "X-Send-PSK";

async function postData(url = "", data = {}) {
  // Default options are marked with *
  const response = await fetch(url, {
    method: "POST",
    cache: "no-cache", // *default, no-cache, reload, force-cache, only-if-cached
    headers: {
      "Content-Type": "application/json",
      [PRESHARED_AUTH_HEADER_KEY]: ENV.parsed.ADMIN_TOKEN,
    },
    body: JSON.stringify(data),
  });
  return response;
}

async function getData(url = "") {
  // Default options are marked with *
  const response = await fetch(url, {
    method: "GET",
    cache: "no-cache", // *default, no-cache, reload, force-cache, only-if-cached
    headers: {
      "Content-Type": "application/json",
    },
  });
  return response;
}

const testAddClaimLinks = async () => {
  const d = new Date();
  const data = {
    claimDate: `${d.getUTCFullYear()}-${d.getUTCMonth()}-${d.getUTCDay()}`,
    links: [
      {
        claimed: false,
        url: "https://www.google.com/",
        by: "0x0",
      },
      {
        claimed: false,
        url: "https://blas2",
        by: "0x0",
      },
      {
        claimed: false,
        url: "https://asdas",
        by: "0x0",
      },
    ],
  };
  await postData(`${endpointUrl}/add-claim-links`, data);
};

const testCanClaimLink = async () => {
  const d = new Date();
  const data = {
    claimDate: `${d.getUTCFullYear()}-${d.getUTCMonth() + 1}-${d.getUTCDate()}`,
  };
  return await postData(`${endpointUrl}/can-claim-links`, data);
};

(async (_) => {
  //await testAddClaimLinks();
  //const a = await testCanClaimLink();
  //console.log(await a.json());
})();
