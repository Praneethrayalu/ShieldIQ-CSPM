(function () {
  var d = document.documentElement; d.classList.add("js");
  try { var t = localStorage.getItem("shieldiq-theme"); if (t) d.setAttribute("data-theme", t); } catch (e) {}
})();
