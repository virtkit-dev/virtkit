// vk-hub web UI: a button with `data-check="all"` or `data-check="none"` checks or unchecks
// every checkbox of its fieldset, such as the nodes a rollout updates. Listening on the
// document, it serves fieldsets swapped in later too. Without this script the boxes are
// checked one by one.
// Loaded as a file: the policy allows no inline script, and nothing here evaluates code.
(function () {
  "use strict";

  document.addEventListener("click", function (e) {
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
})();
