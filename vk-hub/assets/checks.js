// vk-hub web UI: a button with `data-check="all"` or `data-check="none"` checks or unchecks
// every checkbox of its fieldset, such as the nodes a rollout updates. In a
// `<fieldset data-runs-on>`, a lane's selection of pools and nodes, its `#runs-on` line
// follows the boxes ticked: the union of each ticked box's `data-nodes`. A `data-dismiss`
// button, such as a question's Cancel, empties `#flash`; every message swapped into `#flash`
// gets one, as the flash stays pinned to the window until dismissed. An opened
// `<details data-keep>` stays open across live updates. Listening on the document, it serves
// what is swapped in later too. Without this script the boxes are
// checked one by one and a message stays until replaced.
// Loaded as a file: the policy allows no inline script, and nothing here evaluates code.
(function () {
  "use strict";

  function flash() {
    return document.getElementById("flash");
  }

  function closable() {
    var f = flash();
    if (f === null || f.firstChild === null || f.querySelector("[data-dismiss]") !== null) {
      return;
    }
    var button = document.createElement("button");
    button.type = "button";
    button.className = "secondary";
    button.setAttribute("data-dismiss", "");
    button.setAttribute("aria-label", "Dismiss");
    button.textContent = "\u00d7";
    f.appendChild(button);
  }
  document.addEventListener("htmx:oobAfterSwap", closable);
  document.addEventListener("htmx:afterSwap", closable);

  // The nodes a lane's ticked pools and nodes resolve to, as the server lists them on load.
  function runsOn(fieldset) {
    var line = fieldset.querySelector("#runs-on");
    var out = line === null ? null : line.querySelector("span");
    if (out === null) {
      return;
    }
    var boxes = fieldset.querySelectorAll("input[type=checkbox][data-nodes]");
    var seen = {};
    var names = [];
    for (var i = 0; i < boxes.length; i++) {
      if (!boxes[i].checked) {
        continue;
      }
      var members = boxes[i].getAttribute("data-nodes").split("\n");
      for (var j = 0; j < members.length; j++) {
        if (members[j] !== "" && !Object.prototype.hasOwnProperty.call(seen, members[j])) {
          seen[members[j]] = true;
          names.push(members[j]);
        }
      }
    }
    // A pool typed in resolves on the server: until saved, it adds no node here.
    out.textContent = names.length === 0 ? "no node" : names.join(", ");
    line.className = names.length === 0 ? "bad" : "";
  }
  document.addEventListener("change", function (e) {
    var fieldset = e.target instanceof Element ? e.target.closest("fieldset[data-runs-on]") : null;
    if (fieldset !== null) {
      runsOn(fieldset);
    }
  });

  document.addEventListener("click", function (e) {
    var dismiss = e.target instanceof Element ? e.target.closest("[data-dismiss]") : null;
    if (dismiss !== null && flash() !== null && flash().contains(dismiss)) {
      flash().className = "";
      flash().textContent = "";
      return;
    }
    var button = e.target instanceof Element ? e.target.closest("button[data-check]") : null;
    var fieldset = button === null ? null : button.closest("fieldset");
    if (fieldset === null) {
      return;
    }
    var on = button.getAttribute("data-check") === "all";
    var boxes = fieldset.querySelectorAll("input[type=checkbox]");
    for (var i = 0; i < boxes.length; i++) {
      boxes[i].checked = on;
    }
  });

  // A `<details data-keep="<key>">` a live update replaces stays as the viewer left it.
  var kept = {};
  document.addEventListener(
    "toggle",
    function (e) {
      var key = e.target instanceof Element ? e.target.getAttribute("data-keep") : null;
      if (key !== null) {
        kept[key] = e.target.open;
      }
    },
    true
  );
  function reopen() {
    var all = document.querySelectorAll("details[data-keep]");
    for (var i = 0; i < all.length; i++) {
      var key = all[i].getAttribute("data-keep");
      if (kept[key] === true && !all[i].open) {
        all[i].open = true;
      }
    }
  }
  document.addEventListener("htmx:afterSwap", reopen);
  document.addEventListener("htmx:afterSettle", reopen);
  document.addEventListener("htmx:sseMessage", reopen);
})();
