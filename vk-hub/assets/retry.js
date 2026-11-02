// vk-hub web UI: an htmx post the hub did not answer — its connection refused or cut, as while
// the hub restarts or hands over to a release, or a 502, 503 or 504 from a proxy in front of it
// rather than from the hub — says so in `#flash` and is sent again, the same fields and headers,
// after 1, 2, 4 then every 8 seconds, for a minute; then a button sends it again on demand.
// Posts wait in the order they were made and go one at a time, so the last click lands last:
// while any waits, a post made meanwhile waits behind it rather than going ahead, and a click
// while they wait for the button sends them again at once. The same post made twice waits
// once. Without this script such a post shows nothing.
//
// A post is sent again only when no answer came, so it may have reached the hub; a second copy
// must then do what the first would have. Each htmx post of these pages sets a state, which a
// second one finds set; issues a node's command — a reboot or a reset, sent again, may run
// twice; starts what is refused while under way, such as a fetch or `vk dev up`; or answers a
// question the hub asked first and takes once, a second answer being told so. A post for which
// that would not do must not be an htmx one. Plain form posts — a release's upload, a key's or
// token's creation — are the browser's own, and are never sent again here. A post whose form a
// live update replaced while it was under way fails unseen: its events no longer reach the
// document.
// Loaded as a file: the policy allows no inline script, and nothing here evaluates code.
(function () {
  "use strict";

  if (typeof htmx === "undefined") {
    return;
  }

  // Retry budget from the first failure, and maximum delay between retries.
  var PATIENCE = 60 * 1000;
  var LONGEST = 8 * 1000;

  // Oldest first. A resend that connects but never gets an answer blocks the queue:
  // htmx has no timeout.
  var waiting = [];
  // When the first of them failed, how many times it was sent again, and whether it waits for
  // the button.
  var since = 0;
  var tries = 0;
  var stalled = false;

  function say(text, kind, again) {
    var flash = document.getElementById("flash");
    if (flash === null) {
      return;
    }
    flash.className = kind;
    flash.textContent = text;
    if (again) {
      var button = document.createElement("button");
      button.type = "button";
      button.textContent = "Send again";
      button.addEventListener("click", again);
      flash.appendChild(button);
    }
  }

  function send() {
    var post = waiting[0];
    post.failing = false;
    // Use the body because a live update may have replaced the form. Saved values and headers
    // carry the request; events report failures, so the rejected promise adds nothing.
    htmx
      .ajax("POST", post.path, {
        source: document.body,
        values: post.values,
        headers: post.headers,
        swap: "none",
      })
      .catch(function () {});
  }

  // Send the waiting posts again from now on, once the button or a new click asks to.
  function resume() {
    if (stalled) {
      stalled = false;
      since = Date.now();
      tries = 0;
      say("Sending it again…", "warn");
      send();
    }
  }

  // Wait, then send the first post again; past PATIENCE, leave it to the button.
  function later() {
    var wait = Math.min(1000 * Math.pow(2, tries), LONGEST);
    if (Date.now() + wait - since > PATIENCE) {
      stalled = true;
      say(
        "The hub has not answered for a minute, so this may not have been done. ",
        "error",
        resume
      );
      return;
    }
    tries += 1;
    say(
      "The hub did not answer; it may be restarting. Sending this again in " +
        wait / 1000 +
        " s…",
      "warn"
    );
    setTimeout(send, wait);
  }

  function isPost(detail) {
    return detail.requestConfig !== undefined && detail.requestConfig.verb === "post";
  }

  // The post waiting to be sent again that `detail` is about, if it is the one sent.
  function sent(detail) {
    var post = waiting[0];
    return post !== undefined && detail.etc !== undefined && detail.etc.values === post.values
      ? post
      : null;
  }

  // Queue the post `config` describes, unless the same one waits already.
  function queue(config) {
    var values = {};
    config.formData.forEach(function (value, name) {
      (values[name] = values[name] || []).push(value);
    });
    var headers = {};
    for (var name in config.headers) {
      headers[name] = config.headers[name];
    }
    var key = config.path + "\n" + JSON.stringify(values);
    for (var i = 0; i < waiting.length; i++) {
      if (waiting[i].key === key) {
        return;
      }
    }
    waiting.push({ key: key, path: config.path, values: values, headers: headers });
  }

  // A post that failed: the one sent again waits on, another joins the queue.
  function failed(detail) {
    var post = sent(detail);
    if (post !== null) {
      post.failing = true;
      later();
      return;
    }
    queue(detail.requestConfig);
    if (waiting.length === 1) {
      since = Date.now();
      tries = 0;
      later();
    }
  }

  // A post made while others wait goes behind them, rather than ahead of a click made earlier.
  document.addEventListener("htmx:beforeRequest", function (e) {
    if (waiting.length === 0 || !isPost(e.detail) || sent(e.detail) !== null) {
      return;
    }
    e.preventDefault();
    queue(e.detail.requestConfig);
    if (stalled) {
      resume();
    } else {
      say("Waiting for the hub: this goes once what was clicked before it has.", "warn");
    }
  });

  document.addEventListener("htmx:sendError", function (e) {
    if (isPost(e.detail)) {
      failed(e.detail);
    }
  });

  // The hub's own answers swap in `#flash`; a gateway's error page does not.
  document.addEventListener("htmx:beforeSwap", function (e) {
    var xhr = e.detail.xhr;
    var gateway = xhr.status === 502 || xhr.status === 503 || xhr.status === 504;
    if (gateway && isPost(e.detail) && xhr.responseText.indexOf('id="flash"') < 0) {
      e.detail.shouldSwap = false;
      failed(e.detail);
    }
  });

  // The hub answered the post sent again: the next one goes at once.
  document.addEventListener("htmx:afterOnLoad", function (e) {
    var post = sent(e.detail);
    if (post === null || post.failing) {
      return;
    }
    waiting.shift();
    tries = 0;
    since = Date.now();
    if (waiting.length > 0) {
      send();
      return;
    }
    // Our own line, should the answer not have replaced it.
    var flash = document.getElementById("flash");
    if (flash !== null && flash.className === "warn") {
      flash.className = "";
      flash.textContent = "";
    }
  });
})();
