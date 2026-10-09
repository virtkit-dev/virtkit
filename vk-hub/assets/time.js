// vk-hub web UI: each <time datetime> shown in the browser's own time zone with how long
// ago it was, or how soon it is ("11:52 · 5 min ago"; the date too when not today), kept up
// to date as the page's fragments are swapped in and as time passes. The page states the
// UTC instant in each element's text and title, which is what shows without this script.
// Loaded as a file: the policy allows no inline script, and nothing here evaluates code.
(function () {
  "use strict";

  var clock = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" });
  var thisYear = new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
  var otherYear = new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

  // `at`, local: its time alone today, its date too otherwise.
  function when(at, now) {
    if (at.toDateString() === now.toDateString()) {
      return clock.format(at);
    }
    if (at.getFullYear() === now.getFullYear()) {
      return thisYear.format(at);
    }
    return otherYear.format(at);
  }

  // How far `secs` is from now, past when positive: under a minute in steps of 5 seconds, a
  // heartbeat, as the server's text does, then in whole minutes, hours or days.
  function distance(secs) {
    var s = Math.abs(secs);
    var n;
    var unit;
    // A few seconds either way is the clocks' and the network's doing.
    if (s < 10) {
      return "just now";
    }
    if (s < 60) {
      return secs >= 0 ? Math.floor(s / 5) * 5 + "s ago" : "in under a minute";
    }
    if (s < 3600) {
      n = Math.floor(s / 60);
      unit = "min";
    } else if (s < 86400) {
      n = Math.floor(s / 3600);
      unit = "h";
    } else {
      n = Math.floor(s / 86400);
      unit = n === 1 ? "day" : "days";
    }
    return secs >= 0 ? n + " " + unit + " ago" : "in " + n + " " + unit;
  }

  // How far the browser's clock is behind the hub's, from the hub's time the page was
  // built at: ages are the hub's, not those of a browser whose clock is off.
  var served = Date.parse(document.documentElement.getAttribute("data-now") || "");
  var skew = isNaN(served) ? 0 : served - Date.now();
  // Under 2 seconds is the page's own trip and the hub's rounding, not a clock that is off.
  if (Math.abs(skew) < 2000) {
    skew = 0;
  }

  function show() {
    var now = new Date(Date.now() + skew);
    var all = document.querySelectorAll("time[datetime]");
    for (var i = 0; i < all.length; i++) {
      var ms = Date.parse(all[i].getAttribute("datetime"));
      if (isNaN(ms)) {
        continue;
      }
      var text = when(new Date(ms), now) + " · " + distance((now.getTime() - ms) / 1000);
      // Written only when it changes: a page with nothing new is left alone.
      if (all[i].textContent !== text) {
        all[i].textContent = text;
      }
    }
  }

  show();
  // A fragment swapped in, by a request or a live update, comes with the server's text.
  document.addEventListener("htmx:afterSwap", show);
  document.addEventListener("htmx:oobAfterSwap", show);
  // The minutes move on.
  setInterval(show, 5000);
})();
