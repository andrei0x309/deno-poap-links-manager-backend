// Hack To replace missing LocalStorage
// @ts-expect-error Is Deno, Window is mutable
window.LocalStorage = {
  // @ts-expect-error deno part of the cloud function
  getItem: Deno.env.get,
  // @ts-expect-error deno part of the cloud function
  setItem: Deno.env.set,
};
// @ts-expect-error Is Deno, Window is mutable
window.localStorage = LocalStorage;
// Hack to prevent error in gotrue lib
// @ts-expect-error Is Deno, Window is mutable
window.location = { href: "" };

// @ts-expect-error Valid Deno Import
import { ethers } from "https://cdn.ethers.io/lib/ethers-5.1.esm.min.js";
// @ts-expect-error Valid Deno Import
import { createClient } from "https://deno.land/x/supabase/mod.ts";
// @ts-expect-error Valid Deno Import
import { createHash } from "https://deno.land/std@0.77.0/hash/mod.ts";
import {
  json,
  serve,
  validateRequest,
  // @ts-expect-error Valid Deno Import
} from "https://deno.land/x/sift@0.3.5/mod.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, CUSTOM-AUTH-PSK',
  Allow: 'GET, HEAD, POST, OPTIONS',
};

const corsJSON = function (data = {}, reqOpt: any = {}) {
  if ('headers' in reqOpt) {
    reqOpt.headers = {
      ...reqOpt.headers,
      ...corsHeaders
    }
  } else {
    reqOpt.headers = corsHeaders;
  }
  return json(data, reqOpt);
}


// @ts-expect-error deno part of the cloud function
const supabase = createClient("https://jlhzsagrixiqdexxzqoy.supabase.co", Deno.env.get("SUPA_KEY"));

serve({
  "/require-auth-check": handleRequireAuth, // has RequireAuth base
  "/admin-login": handleAdminLogin, // has RequireAuth base
  "/add-claim-links": handleAddClaimLinks, // RequireAuth
  "/get-claim-links": handleGetClaimLinks, // RequireAuth
  "/del-claim-links": handleDelClaimLinks, // RequireAuth
  "/get-claim-link": handleGetClaimLink, // RequireAuth
  "/add-past-event": handleAddPastEvent, // RequireAuth
  "/del-past-event": handleDelPastEvent, // RequireAuth
  "/edit-past-event": handleEditPastEvent, // RequireAuth
  "/get-claim-pass": handleGetClaimPass, // RequireAuth
  "/set-claim-pass": handleSetClaimPass, // RequireAuth
  "/get-past-event": handleGetPastEvent, // RequireAuth
  "/can-claim-links": handleCanClaimLinks, // NO RequireAuth
  "/request-claim-link": handleClaimLink, // NO RequireAuth
  "/get-past-events": handleGetPastEvents, // NO RequireAuth
  "/get-past-meetings": handleGetPastMeetings, // NO RequireAuth
  "/get-notes-meeting": handleGetNotesMeeting // NO RequireAuth

});


async function logValidAttemptClaim(claim) {
  await supabase.from("claim-attempts").insert([claim]);
}

async function requireAuth(request: Request) {
  const authPass = request.headers.get("CUSTOM-AUTH-PSK");
  if (!authPass) {
    return corsJSON({ error: "Unauthorized 401 !" }, { status: 401 });
  }
  const dbAdminPass = (await supabase.from("settings").select("*").eq("settingName", "admin-password")).data[0].settingValue;
  const hash = createHash("sha256");
  hash.update(authPass);
  const hashString = hash.toString();
  if (hashString !== dbAdminPass) {
    return corsJSON({ error: "Unauthorized 401 !" }, { status: 401 });
  }
}

async function handleOptHead(request: Request) {
  if (request.method === 'OPTIONS' || request.method === 'HEAD') {
    return corsJSON({ ok: true });
  }
}

async function handleRequireAuth(request: Request) {
  const isOptHead = await handleOptHead(request);
  if (isOptHead instanceof Response) return isOptHead;
  const isReqAuth = await requireAuth(request);
  if (isReqAuth instanceof Response) return isReqAuth;
  return corsJSON({ ok: true, msg: "Success!" });
}

async function handleAdminLogin(request: Request) {
  const isOptHead = await handleOptHead(request);
  if (isOptHead instanceof Response) return isOptHead;
  const data = await request.json();
  if (!("password" in data)) {
    return corsJSON({ error: "Missing param password" }, { status: 401 });
  }
  const dbAdminPass = (await supabase.from("settings").select("*").eq("settingName", "admin-password")).data[0].settingValue;
  const hash = createHash("sha256");
  hash.update(data.password);
  const hashString = hash.toString();
  if (hashString !== dbAdminPass) {
    return corsJSON({ error: "Unauthorized 401 !" }, { status: 401 });
  }
  return corsJSON({ ok: true, msg: "Success!" });
}

async function handleGetClaimPass(request: Request) {
  const isOptHead = await handleOptHead(request);
  if (isOptHead instanceof Response) return isOptHead;
  const isReqAuth = await requireAuth(request);
  if (isReqAuth instanceof Response) return isReqAuth;
  let select = await supabase
    .from("settings")
    .select('*')
    .eq("settingName", "claim-password");
  if (select.error) {
    return corsJSON({ error: select.error }, { status: 500 });
  }
  return corsJSON({ password: select.data[0].settingValue });
}

async function handleSetClaimPass(request: Request) {
  const isOptHead = await handleOptHead(request);
  if (isOptHead instanceof Response) return isOptHead;
  const isReqAuth = await requireAuth(request);
  if (isReqAuth instanceof Response) return isReqAuth;
  const data = await request.json();
  if (!("password" in data)) {
    return corsJSON({ error: "Missing param password" }, { status: 401 });
  }
  let update = await supabase
    .from("settings")
    .update({
      settingValue: data.password,
    })
    .eq("settingName", "claim-password");
  if (update.error) {
    return corsJSON({ error: "DB ERROR" }, { status: 500 });
  }
  return corsJSON({ msg: "Claim password Set" });
}

async function handleGetClaimLinks(request: Request) {
  const isOptHead = await handleOptHead(request);
  if (isOptHead instanceof Response) return isOptHead;
  const isReqAuth = await requireAuth(request);
  if (isReqAuth instanceof Response) return isReqAuth;
  let select = await supabase.from("claim-links").select('*');
  if (select.error) {
    return corsJSON({ error: select.error }, { status: 500 });
  }
  return corsJSON(select);
}

async function handleGetClaimLink(request: Request) {
  const isOptHead = await handleOptHead(request);
  if (isOptHead instanceof Response) return isOptHead;
  const isReqAuth = await requireAuth(request);
  if (isReqAuth instanceof Response) return isReqAuth;
  const data = await request.json();
  if (!('id' in data)) {
    return corsJSON({ error: "Missing param id." }, { status: 401 });
  }
  let select = await supabase.from("claim-links").select('*').eq("id", data.id);
  if (select.error) {
    return corsJSON({ error: select.error }, { status: 500 });
  }
  return corsJSON(select.data[0]);
}

async function handleDelClaimLinks(request: Request) {
  const isOptHead = await handleOptHead(request);
  if (isOptHead instanceof Response) return isOptHead;
  const isReqAuth = await requireAuth(request);
  if (isReqAuth instanceof Response) return isReqAuth;
  const data = await request.json();
  if (!("id" in data)) {
    return corsJSON({ error: "Missing param id" }, { status: 401 });
  }
  const delCmd = await supabase.from("claim-links").delete('*').match({ id: data.id });
  if (delCmd.error) {
    return corsJSON({ error: delCmd.error }, { status: 500 });
  }
  return corsJSON({ msg: `Claim-link entitty with id ${data.id} deleted` });
}

async function handleAddClaimLinks(request: Request) {
  const isOptHead = await handleOptHead(request);
  if (isOptHead instanceof Response) return isOptHead;
  const isReqAuth = await requireAuth(request);
  if (isReqAuth instanceof Response) return isReqAuth;
  const data = await request.json();
  let insert = await supabase.from("claim-links").insert([data]);
  if (insert.error) {
    return corsJSON({ error: "DB ERROR" }, { status: 500 });
  }
  return corsJSON({ msg: "Links Added" });
}

async function handleAddPastEvent(request: Request) {
  const isOptHead = await handleOptHead(request);
  if (isOptHead instanceof Response) return isOptHead;
  const isReqAuth = await requireAuth(request);
  if (isReqAuth instanceof Response) return isReqAuth;
  const data = await request.json();
  if (!('url' in data) || !('description' in data) || !('date' in data)) {
    return corsJSON({ error: "Missing param url or description or date." }, { status: 401 });
  }
  let insert = await supabase.from("past-events").insert([data]);
  if (insert.error) {
    return corsJSON({ error: insert.error }, { status: 500 });
  }
  return corsJSON({ msg: "Past Event added" });
}

async function handleDelPastEvent(request: Request) {
  const isOptHead = await handleOptHead(request);
  if (isOptHead instanceof Response) return isOptHead;
  const isReqAuth = await requireAuth(request);
  if (isReqAuth instanceof Response) return isReqAuth;
  const data = await request.json();
  if (!("id" in data)) {
    return corsJSON({ error: "Missing param id" }, { status: 401 });
  }
  const delCmd = await supabase.from("past-events").delete('*').match({ id: data.id });
  if (delCmd.error) {
    return corsJSON({ error: delCmd.error }, { status: 500 });
  }
  return corsJSON({ msg: `Past-event entitty with id ${data.id} deleted` });
}


async function handleEditPastEvent(request: Request) {
  const isOptHead = await handleOptHead(request);
  if (isOptHead instanceof Response) return isOptHead;
  const isReqAuth = await requireAuth(request);
  if (isReqAuth instanceof Response) return isReqAuth;
  const data = await request.json();
  if (!('id' in data)) {
    return corsJSON({ error: "Missing param id." }, { status: 401 });
  }
  if (!('url' in data) || !('description' in data) || !('date' in data)) {
    return corsJSON({ error: "Missing param url or description or date." }, { status: 401 });
  }
  let update = await supabase
    .from("past-events")
    .update({
      url: data.url,
      date: data.date,
      description: data.description
    })
    .match({ id: data.id });
  if (update.error) {
    return corsJSON({ error: update.error }, { status: 500 });
  }
  return corsJSON({ msg: "Past Event Edited" });

}

async function handleCanClaimLinks(request: Request) {
  const isOptHead = await handleOptHead(request);
  if (isOptHead instanceof Response) return isOptHead;
  const data = await request.json();
  const claimDate = data.claimDate;

  if (!claimDate) {
    return corsJSON({ error: "Claim date string not found" }, { status: 401 });
  }
  if (!claimDate.match(/\d{4}\-\d{1,2}\-\d{1,2}/)) {
    return corsJSON({ error: "Claim date string format incorect" }, { status: 401 });
  }

  let getClaimLinks = await supabase.from("claim-links").select("*").eq("claimDate", claimDate);
  if (getClaimLinks.error) {
    return corsJSON({ can: false });
  }
  return corsJSON({ can: Boolean(getClaimLinks.data.length) });
}

async function handleClaimLink(request: Request) {
  const isOptHead = await handleOptHead(request);
  if (isOptHead instanceof Response) return isOptHead;
  const data = await request.json();
  const claimDate = data.claimDate;
  const claimPassword = data.claimPassword;
  let claimEth = data.claimEth;

  const logAttemptSchema = {
    error: "",
    app_code: claimPassword,
    poap_link: "",
    eth: claimEth,
    attempt_date: claimDate
  };
  const msgForAttempt = `There was an error trying to automatically claim the POAP. But fear not since the code [ ${claimPassword} ] was valid your attempt was logged and the system will automatically claim the POAP later in [ ${claimEth} ] wallet.`


  if (!claimDate) {
    return corsJSON({ error: "Claim date string not found." }, { status: 401 });
  }
  if (!claimPassword) {
    return corsJSON({ error: "Claim code string not found." }, { status: 401 });
  }
  if (!claimEth) {
    return corsJSON({ error: "Claim ETH or ESN string not found." }, { status: 401 });
  }
  const isENS = claimEth.endsWith('.eth');
  if (!(claimEth.match(/^0x[a-fA-F0-9]{40}$/) || isENS)) {
    return corsJSON({ error: "Invalid ETH or ENS string." }, { status: 401 });
  }

  if (!claimDate.match(/\d{4}\-\d{1,2}\-\d{1,2}/)) {
    return corsJSON({ error: "Claim date string format incorect" }, { status: 401 });
  }

  //  const dbClaimPassword = (await supabase.from("settings").select("*").eq("settingName", "claim-password")).data[0]
  //    .settingValue;
  //  if (claimPassword !== dbClaimPassword) {
  //    return corsJSON({ error: "Invalid claim password." }, { status: 401 });
  //  }

  const network = "homestead";
  const provider = ethers.getDefaultProvider(network, {
    infura: {
      projectId: "191666b114a64a0eb2fbfa30d5aef1a9",
      // @ts-expect-error deno part of the cloud function
      projectSecret: Deno.env.get("INFURA_KEY"),
    },
  });

  if (isENS) {
    claimEth = await provider.resolveName(claimEth);
  }
  try {
    ethers.utils.getAddress(claimEth);
  } catch (_) {
    return corsJSON({ error: "Your ETH Address OR ENS Name is invalid." }, { status: 401 });
  }

  let getClaimLinks = await supabase.from("claim-links").select("*").eq("claimDate", claimDate);

  if (getClaimLinks.error || !getClaimLinks.data.length) {
    return corsJSON({ error: "No links with this claim date found." }, { status: 401 });
  }

  const links = getClaimLinks.data[0].links;

  const checkCode = links.filter((el) => String(el.code) === claimPassword);
  console.log(checkCode);
  if (!checkCode.length) {
    return corsJSON({ error: "Code is invalid." }, { status: 401 });
  }

  const alreadyClaimed = links.filter((el) => el.by === claimEth);
  if (alreadyClaimed.length) {
    logAttemptSchema.error = "You already claimed this POAP.";
    logAttemptSchema.poap_link = alreadyClaimed[0].url;
    logValidAttemptClaim(logAttemptSchema);
    return corsJSON({ error: msgForAttempt }, { status: 500 });
  }

  if (checkCode[0].by !== "") {
    logAttemptSchema.error = "Code is already used.";
    logAttemptSchema.poap_link = checkCode[0].url;
    logValidAttemptClaim(logAttemptSchema);
    return corsJSON({ error: msgForAttempt }, { status: 500 });
  }

  let linkObj = null;
  for (const [index, value] of links.entries()) {
    if (value.claimed === false) {
      getClaimLinks.data[0].links[index].claimed = true;
      getClaimLinks.data[0].links[index].by = claimEth;
      linkObj = getClaimLinks.data[0].links[index];
      break;
    }
  }
  const updateLinks = await supabase.from("claim-links").update(getClaimLinks.data).eq("id", getClaimLinks.data[0].id);

  if (updateLinks.error) {
    logAttemptSchema.error = "Database error updating the claim links";
    logAttemptSchema.poap_link = checkCode[0].url;
    logValidAttemptClaim(logAttemptSchema);
    return corsJSON({ error: msgForAttempt }, { status: 500 });
  }
  if (linkObj) {
    logAttemptSchema.error = "Code maybe not be claimed.";
    logAttemptSchema.poap_link = checkCode[0].url;
    logValidAttemptClaim(logAttemptSchema);
    return corsJSON({ link: linkObj.url, by: linkObj.by, msg: "Success!" });
  }

  logAttemptSchema.error = "Sorry No more links to be claimed";
  logAttemptSchema.poap_link = checkCode[0].url;
  logValidAttemptClaim(logAttemptSchema);
  return corsJSON({ error: msgForAttempt }, { status: 500 });
}

async function handleGetPastEvents(request: Request) {
  const isOptHead = await handleOptHead(request);
  if (isOptHead instanceof Response) return isOptHead;

  let select = await supabase.from("past-events").select('*').order('created_at', { ascending: false });
  if (select.error) {
    return corsJSON({ error: select.error }, { status: 500 });
  }
  return corsJSON(select);
}

async function handleGetPastMeetings(request: Request) {
  const isOptHead = await handleOptHead(request);
  if (isOptHead instanceof Response) return isOptHead;

  const data = await request.json();
  let limitRecords = 50;
  if ('limit' in data && !isNaN(Number(data.limt)) && Number(data.limt) > 0 && Number(data.limt) <= 50) {
    limitRecords = Number(data.limt)
  }
  let select = await supabase.from("meetings-videos").select('*').order('created_at', { ascending: false }).limit(limitRecords);
  if (select.error) {
    return corsJSON({ error: select.error }, { status: 500 });
  }
  return corsJSON(select);
}

async function handleGetNotesMeeting(request: Request) {
  const isOptHead = await handleOptHead(request);
  if (isOptHead instanceof Response) return isOptHead;

  const data = await request.json();
  if (!('notesUrl' in data)) {
    return corsJSON({ error: "No NOTE URL" }, { status: 401 });
  }
  if (data.notesUrl.includes('yup.community')) {
    return corsJSON({ error: "Be nice!" }, { status: 401 });
  }
  return fetch(data.notesUrl)
}

async function handleGetPastEvent(request: Request) {
  const isOptHead = await handleOptHead(request);
  if (isOptHead instanceof Response) return isOptHead;
  const isReqAuth = await requireAuth(request);
  if (isReqAuth instanceof Response) return isReqAuth;
  const data = await request.json();
  if (!('id' in data)) {
    return corsJSON({ error: "Missing param id." }, { status: 401 });
  }
  let select = await supabase.from("past-events").select('*').eq("id", data.id);
  if (select.error) {
    return corsJSON({ error: select.error }, { status: 500 });
  }
  return corsJSON(select.data[0]);
}

