// vk-hub web UI: a running job's output, `<pre data-follow>`, kept scrolled to its end as
// lines are appended to it, for as long as the reader is there: scrolled up to read, it stays
// put until scrolled back down. It opens at its end. Without this script the output still
// grows; it is only not scrolled. The page keeps the output's last 2 MiB of text or so: past
// it, the oldest lines go, a note at the start says so, and the lines left keep their numbers.
// Loaded as a file: the policy allows no inline script, and nothing here evaluates code.
(function () {
  "use strict";

  // Within this many pixels of its end counts as at it.
  var SLACK = 24;

  // The most text the output keeps, in characters; trimmed to three quarters of it at once.
  var BUDGET = 2 * 1024 * 1024;

  function output() {
    return document.querySelector("pre[data-follow]");
  }

  function atEnd(pre) {
    return pre.scrollHeight - pre.scrollTop - pre.clientHeight <= SLACK;
  }

  function toEnd(pre) {
    pre.scrollTop = pre.scrollHeight;
  }

  // Whether the output was at its end before a live update was swapped in.
  var following = true;

  // Lines dropped since the stream last replaced the output. Offset the `ui.css` counter
  // for each `.l` by this count to preserve the remaining line numbers.
  var dropped = 0;

  document.addEventListener("htmx:sseBeforeMessage", function () {
    var pre = output();
    following = pre !== null && atEnd(pre);
  });

  // Drop the oldest lines past BUDGET, whole, and say so in the note at the start.
  function trim() {
    var lines = document.getElementById("job-lines");
    if (lines === null) {
      return;
    }
    var size = lines.textContent.length;
    if (size <= BUDGET) {
      return;
    }
    var note = lines.querySelector(".cut");
    var node = note !== null ? note.nextSibling : lines.firstChild;
    var ended = false;
    while (node !== null && (size > BUDGET * 3 / 4 || !ended)) {
      var next = node.nextSibling;
      var text = node.textContent;
      size -= text.length;
      ended = node.nodeType === Node.TEXT_NODE && text.charAt(text.length - 1) === "\n";
      if (node.nodeType === Node.ELEMENT_NODE && node.classList.contains("l")) {
        dropped += 1;
      }
      lines.removeChild(node);
      node = next;
    }
    if (note === null) {
      note = document.createElement("span");
      note.className = "cut";
      lines.insertBefore(note, lines.firstChild);
    }
    note.textContent = "\u2026 earlier output not shown";
    var after = note.nextSibling;
    var broken = after === null || after.nodeType !== Node.TEXT_NODE;
    if (broken || after.textContent.charAt(0) !== "\n") {
      lines.insertBefore(document.createTextNode("\n"), after);
    }
    number();
  }

  // Start the numbering after the lines dropped. Through the CSSOM, which the policy allows,
  // unlike a style attribute.
  function number() {
    var pre = output();
    if (pre !== null) {
      pre.style.counterReset = dropped > 0 ? "line " + dropped : "";
    }
  }

  document.addEventListener("htmx:sseMessage", function (e) {
    // A stream's first event replaces every line: numbered from the first again.
    if (e.detail && e.detail.type === "output-start") {
      dropped = 0;
      number();
    }
    var pre = output();
    // Scrolled up to read: keep the lines in view where they are as the oldest go.
    var height = pre !== null ? pre.scrollHeight : 0;
    trim();
    if (pre !== null && !following) {
      pre.scrollTop -= height - pre.scrollHeight;
    }
    if (pre !== null && following) {
      toEnd(pre);
    }
  });

  function start() {
    var pre = output();
    if (pre !== null) {
      toEnd(pre);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
