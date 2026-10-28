// Window logic. Card and file work happens in Rust (src/main.rs) through
// `invoke`; this file only collects input and shows results.

const { invoke } = window.__TAURI__.core;
const { open, save } = window.__TAURI__.dialog;

const $ = (id) => document.getElementById(id);
const pdfFilter = [{ name: "PDF", extensions: ["pdf"] }];
const baseName = (p) => p.split(/[\\/]/).pop();

let input = null;
let output = null;
let card = null;

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  Object.assign(node, attrs);
  node.append(...children);
  return node;
}

// Shows an error from Rust: a short message, with the technical details
// (reader names, card answers) folded away for when someone asks for them.
function showError(target, e, prefix = "") {
  const message = e?.message ?? `${prefix}${e}`;
  target.className = "bad";
  target.replaceChildren(message);
  if (e?.details) {
    target.append(
      el(
        "details",
        { className: "error-details" },
        el("summary", { textContent: "Detalles" }),
        el("pre", { textContent: e.details }),
      ),
    );
  }
}

// --- Card -----------------------------------------------------------------

async function refreshCard() {
  $("refresh").disabled = true;
  $("card-status").textContent = "Buscando la cédula…";
  $("card-status").className = "muted";
  $("card-status").hidden = false;
  $("card-details").hidden = true;
  card = null;
  try {
    card = await invoke("card");
    $("card-name").textContent = card.name ?? card.subject;
    $("card-validity").textContent = `${card.valid_from.slice(0, 10)} al ${card.valid_until.slice(0, 10)}`;
    $("card-validity").className = card.expired ? "bad" : "";
    if (card.expired) $("card-validity").textContent += " (vencido)";
    $("card-pin").textContent = card.pin_blocked
      ? "bloqueado"
      : card.pin_tries == null
        ? "ya ingresado"
        : `${card.pin_tries} intentos disponibles`;
    $("card-pin").className = card.pin_blocked || card.pin_tries === 1 ? "bad" : "";
    $("card-status").hidden = true;
    $("card-details").hidden = false;
    $("sig-name").textContent = card.name ?? "tu nombre";
  } catch (e) {
    showError($("card-status"), e);
  }
  $("refresh").disabled = false;
  updateSignButton();
}

// --- Sign -----------------------------------------------------------------

function updateSignButton() {
  const pinOk = /^[0-9]{4,8}$/.test($("pin").value);
  $("sign-button").disabled = !(input && output && card && !card.pin_blocked && pinOk);
}

async function pickInput() {
  const path = await open({ multiple: false, filters: pdfFilter });
  if (!path) return;
  input = path;
  output = await invoke("default_output", { input });
  $("input-name").textContent = baseName(input);
  $("input-name").className = "";
  $("output-name").textContent = baseName(output);
  $("output-row").hidden = false;
  $("sign-result").textContent = "";
  updateSignButton();
  loadPreview();
}

async function pickOutput() {
  const path = await save({ defaultPath: output, filters: pdfFilter });
  if (!path) return;
  output = path;
  $("output-name").textContent = baseName(output);
  updateSignButton();
}

async function sign(event) {
  event.preventDefault();
  const result = $("sign-result");
  const pin = $("pin").value;
  $("pin").value = "";
  $("sign-button").disabled = true;
  $("refresh").disabled = true;
  result.className = "muted";
  result.textContent = $("use-tsa").checked ? "Firmando y pidiendo el sello de tiempo…" : "Firmando…";
  try {
    const saved = await invoke("sign", {
      request: {
        input,
        output,
        pin,
        reason: $("reason").value,
        location: $("location").value,
        visible: $("visible").checked,
        page: place.doc ? place.page : null,
        rect: place.doc ? place.rect : null,
        tsa: $("use-tsa").checked ? $("tsa").value : null,
      },
    });
    result.className = "ok";
    result.textContent = `Listo: ${saved}`;
  } catch (e) {
    showError(result, e, "No se pudo firmar: ");
  }
  // The tries counter may have changed either way.
  await refreshCard();
}

// --- Placing the visible signature ------------------------------------------
//
// The chosen page is drawn with pdf.js (vendored in ui/vendor/pdfjs) and the
// box is dragged over it. The box lives in PDF points (`place.rect`, as
// x1,y1,x2,y2 from the page's lower-left corner), the same numbers the CLI
// takes with --rect; screen positions are derived from it on every redraw.

const DEFAULT_BOX = { width: 220, height: 70, margin: 36 }; // points, as gancho-core
const MIN_BOX = { width: 60, height: 24 };
const MAX_PREVIEW_HEIGHT = 440;

let pdfjs = null;
const place = {
  doc: null, // the PDF as pdf.js opened it
  page: 1,
  count: 0,
  rect: null,
  viewport: null, // the page as drawn: points ↔ CSS pixels
  task: null, // the drawing in progress
  loading: 0, // bumped per file, so a late load for an old file is dropped
  failed: false, // pdf.js could not open the file; the default spot is used
};

async function loadPreview() {
  const loading = ++place.loading;
  place.doc?.destroy();
  Object.assign(place, { doc: null, rect: null, viewport: null, failed: false });
  updatePlacement();
  if (!input) return;
  try {
    if (!pdfjs) {
      pdfjs = await import("./vendor/pdfjs/pdf.min.mjs");
      pdfjs.GlobalWorkerOptions.workerSrc = "vendor/pdfjs/pdf.worker.min.mjs";
    }
    const data = await invoke("read_pdf", { path: input });
    const doc = await pdfjs.getDocument({ data: new Uint8Array(data) }).promise;
    if (loading !== place.loading) return doc.destroy();
    Object.assign(place, { doc, count: doc.numPages, page: doc.numPages });
    updatePlacement();
    await showPage();
  } catch (e) {
    if (loading !== place.loading) return;
    console.error("gancho: preview", e);
    place.failed = true;
    updatePlacement();
  }
}

function updatePlacement() {
  $("placement").hidden = !$("visible").checked || !(place.doc || place.failed);
  for (const id of ["page-view", "page-prev", "page-next", "page-label"]) $(id).hidden = place.failed;
  $("placement-hint").textContent = place.failed
    ? "No se pudo mostrar la vista previa. La firma va abajo a la izquierda de la última página."
    : "Arrastrá el recuadro hasta donde va la firma. Tirá de la esquina para cambiar el tamaño.";
  $("page-label").textContent = `Página ${place.page} de ${place.count}`;
  $("page-prev").disabled = place.page <= 1;
  $("page-next").disabled = place.page >= place.count;
}

async function showPage() {
  if (!place.doc || $("placement").hidden) return;
  const doc = place.doc;
  const page = await doc.getPage(place.page);
  if (doc !== place.doc) return;
  const natural = page.getViewport({ scale: 1 });
  const room = $("page-view").clientWidth - 22; // padding and border
  const scale = Math.min(room / natural.width, MAX_PREVIEW_HEIGHT / natural.height);
  const viewport = page.getViewport({ scale });
  const ratio = window.devicePixelRatio || 1;
  const canvas = $("page-canvas");

  place.task?.cancel();
  canvas.width = Math.floor(viewport.width * ratio);
  canvas.height = Math.floor(viewport.height * ratio);
  canvas.style.width = `${viewport.width}px`;
  canvas.style.height = `${viewport.height}px`;
  place.viewport = viewport;

  if (!place.rect) {
    // Bottom-left of the page as shown, like the CLI's default.
    const s = viewport.scale;
    const w = Math.min(DEFAULT_BOX.width * s, viewport.width);
    const h = Math.min(DEFAULT_BOX.height * s, viewport.height);
    const m = DEFAULT_BOX.margin * s;
    const left = Math.max(0, Math.min(m, viewport.width - w));
    const top = Math.max(0, viewport.height - h - m);
    setBox({ left, top, width: w, height: h });
  } else {
    setBox(boxOnScreen());
  }

  place.task = page.render({ canvas, canvasContext: canvas.getContext("2d"), viewport,
    transform: ratio === 1 ? null : [ratio, 0, 0, ratio, 0, 0] });
  try {
    await place.task.promise;
  } catch (e) {
    if (e?.name !== "RenderingCancelledException") throw e;
  }
}

// `place.rect` as a box on the canvas, in CSS pixels.
function boxOnScreen() {
  const [px1, py1, px2, py2] = place.rect;
  const [x1, y1] = place.viewport.convertToViewportPoint(px1, py1);
  const [x2, y2] = place.viewport.convertToViewportPoint(px2, py2);
  return {
    left: Math.min(x1, x2),
    top: Math.min(y1, y2),
    width: Math.abs(x2 - x1),
    height: Math.abs(y2 - y1),
  };
}

// Puts the box on screen, kept inside the page, and stores it in points.
function setBox({ left, top, width, height }) {
  const vp = place.viewport;
  const minW = Math.min(MIN_BOX.width * vp.scale, vp.width);
  const minH = Math.min(MIN_BOX.height * vp.scale, vp.height);
  width = Math.min(Math.max(width, minW), vp.width);
  height = Math.min(Math.max(height, minH), vp.height);
  left = Math.min(Math.max(left, 0), vp.width - width);
  top = Math.min(Math.max(top, 0), vp.height - height);

  const box = $("sig-box");
  box.style.left = `${left}px`;
  box.style.top = `${top}px`;
  box.style.width = `${width}px`;
  box.style.height = `${height}px`;

  const [ax, ay] = vp.convertToPdfPoint(left, top + height);
  const [bx, by] = vp.convertToPdfPoint(left + width, top);
  const round = (v) => Math.round(v * 10) / 10;
  place.rect = [Math.min(ax, bx), Math.min(ay, by), Math.max(ax, bx), Math.max(ay, by)].map(round);
}

// Drags the box (from its body) or resizes it (from the corner handle).
function startDrag(event) {
  if (event.button !== 0 || !place.viewport) return;
  event.preventDefault();
  const box = $("sig-box");
  box.focus();
  box.setPointerCapture(event.pointerId);
  const resizing = event.target === $("sig-handle");
  const start = { x: event.clientX, y: event.clientY, ...boxOnScreen() };
  const move = (e) => {
    const dx = e.clientX - start.x;
    const dy = e.clientY - start.y;
    setBox(
      resizing
        ? { ...start, width: start.width + dx, height: start.height + dy }
        : { ...start, left: start.left + dx, top: start.top + dy },
    );
  };
  const end = () => {
    box.removeEventListener("pointermove", move);
    box.removeEventListener("pointerup", end);
    box.removeEventListener("pointercancel", end);
  };
  box.addEventListener("pointermove", move);
  box.addEventListener("pointerup", end);
  box.addEventListener("pointercancel", end);
}

// Arrow keys move the box; with Shift they resize it.
function nudgeBox(event) {
  const step = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] }[event.key];
  if (!step || !place.viewport) return;
  event.preventDefault();
  const [dx, dy] = step.map((v) => v * 5);
  const b = boxOnScreen();
  setBox(
    event.shiftKey
      ? { ...b, width: b.width + dx, height: b.height - dy }
      : { ...b, left: b.left + dx, top: b.top + dy },
  );
}

function turnPage(delta) {
  const page = Math.min(Math.max(place.page + delta, 1), place.count);
  if (page === place.page) return;
  place.page = page;
  updatePlacement();
  showPage();
}

let resizeTimer = null;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(showPage, 150);
});

// --- Verify ---------------------------------------------------------------

async function pickVerify() {
  const path = await open({ multiple: false, filters: pdfFilter });
  if (!path) return;
  $("verify-name").textContent = baseName(path);
  $("verify-name").className = "";
  const out = $("verify-result");
  out.replaceChildren(el("p", { className: "muted", textContent: "Verificando…" }));
  try {
    const checks = await invoke("verify", { path });
    if (checks.length === 0) {
      out.replaceChildren(el("p", { className: "bad", textContent: "Este PDF no tiene firmas." }));
      return;
    }
    out.replaceChildren(...checks.map(renderCheck));
  } catch (e) {
    const p = el("p");
    showError(p, e, "No se pudo verificar: ");
    out.replaceChildren(p);
  }
}

function renderCheck(c, i) {
  const lines = [
    c.signer && `Firmante: ${c.signer}`,
    c.time && `Fecha declarada: ${c.time}`,
    c.reason && `Motivo: ${c.reason}`,
    c.location && `Lugar: ${c.location}`,
  ].filter(Boolean);
  return el(
    "div",
    { className: "sig" },
    el("h3", {
      className: c.valid ? "ok" : "bad",
      textContent: `${c.valid ? "✓ Firma válida" : "✗ Firma no válida"} (${c.field ?? `firma ${i + 1}`})`,
    }),
    ...lines.map((t) => el("div", { className: "muted", textContent: t })),
    el("ul", {}, ...c.notes.map((n) => el("li", { className: n.ok ? "" : "bad", textContent: n.text }))),
  );
}

// --- Wiring ---------------------------------------------------------------

function showTab(name) {
  const signing = name === "sign";
  $("tab-sign").setAttribute("aria-selected", signing);
  $("tab-verify").setAttribute("aria-selected", !signing);
  $("sign").hidden = !signing;
  $("verify").hidden = signing;
}

$("refresh").addEventListener("click", refreshCard);
$("tab-sign").addEventListener("click", () => showTab("sign"));
$("tab-verify").addEventListener("click", () => showTab("verify"));
$("pick-input").addEventListener("click", pickInput);
$("pick-output").addEventListener("click", pickOutput);
$("pick-verify").addEventListener("click", pickVerify);
$("pin").addEventListener("input", updateSignButton);
$("visible").addEventListener("change", () => {
  updatePlacement();
  showPage();
});
$("page-prev").addEventListener("click", () => turnPage(-1));
$("page-next").addEventListener("click", () => turnPage(1));
$("sig-box").addEventListener("pointerdown", startDrag);
$("sig-box").addEventListener("keydown", nudgeBox);
$("use-tsa").addEventListener("change", (e) => ($("tsa-row").hidden = !e.target.checked));
$("sign").addEventListener("submit", sign);

refreshCard();
