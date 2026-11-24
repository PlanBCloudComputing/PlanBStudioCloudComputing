/* common.js: helpers shared by every Plan B Studio screen (task P2-S6).
   Purpose: call the JSON API, keep the login token, and show messages.
   Important logic:
     * The token lives in sessionStorage (this browser tab only); the server keeps no session.
     * Text from the API or from users (names, notes) is always put on the page with
       textContent, never innerHTML, so a name like "<script>" cannot run as code.
     * A 401 on a protected page clears the token and goes to the login screen. */
const API = "/api/v1";

function getToken() {
  try { return sessionStorage.getItem("planb_token"); } catch (e) { return null; }
}
function setToken(token) {
  try { sessionStorage.setItem("planb_token", token); } catch (e) { /* storage blocked: stay logged out */ }
}
function clearToken() {
  try { sessionStorage.removeItem("planb_token"); } catch (e) { /* nothing to clear */ }
}

/* Call the API. Returns {status, ok, data}; data is the parsed JSON body or null. */
async function api(method, path, body) {
  const headers = { "Content-Type": "application/json" };
  const token = getToken();
  if (token) headers["Authorization"] = "Bearer " + token;
  let response;
  try {
    response = await fetch(API + path, {
      method: method, headers: headers, body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (e) {
    return { status: 0, ok: false, data: { message: "Cannot reach the server" } };
  }
  let data = null;
  try { data = await response.json(); } catch (e) { /* 204 or empty body */ }
  return { status: response.status, ok: response.ok, data: data };
}

/* Show a message in an element with class "msg". kind is "error" or "ok". */
function showMessage(element, text, kind) {
  element.textContent = text || "";
  element.className = "msg " + (kind || "");
}
function errorText(result) {
  return (result.data && result.data.message) || ("Something went wrong (" + result.status + ")");
}

/* For pages that need a login: go to the login screen if there is no token. */
function requireLogin() {
  if (!getToken()) { window.location.href = "login.html"; return false; }
  return true;
}
function handleUnauthorized(result) {
  if (result.status === 401) { clearToken(); window.location.href = "login.html"; return true; }
  return false;
}

/* Fill the "who am I" label and the logout link in the nav bar. */
async function setupNav() {
  const who = document.getElementById("who");
  const logout = document.getElementById("logout");
  if (!who) return;
  if (!getToken()) { who.textContent = "Not logged in"; if (logout) logout.hidden = true; return; }
  const me = await api("GET", "/users/me");
  who.textContent = me.ok ? me.data.display_name + " (" + me.data.email + ")" : "Not logged in";
  if (logout) {
    logout.hidden = false;
    logout.onclick = function (event) { event.preventDefault(); clearToken(); window.location.href = "login.html"; };
  }
}

/* Small DOM helpers. */
function cell(text, className) {
  const td = document.createElement("td");
  td.textContent = text;
  if (className) td.className = className;
  return td;
}
function queryParam(name) { return new URLSearchParams(window.location.search).get(name) || ""; }
function rememberEvent(id) { try { sessionStorage.setItem("planb_event", id); } catch (e) { /* ignore */ } }
function lastEvent() { try { return sessionStorage.getItem("planb_event") || ""; } catch (e) { return ""; } }
