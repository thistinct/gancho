// Window logic. Card and file work happens in Rust (src/main.rs) through
// `invoke`; this file only collects input and shows results.

const { invoke, Channel } = window.__TAURI__.core;
const { open, save } = window.__TAURI__.dialog;
const { listen } = window.__TAURI__.event;
const { getCurrentWebview } = window.__TAURI__.webview;

const $ = (id) => document.getElementById(id);
const pdfFilter = [{ name: "PDF", extensions: ["pdf"] }];
const baseName = (p) => p.split(/[\\/]/).pop();
const isPdf = (p) => /\.pdf$/i.test(p);

// PDFs to sign, each with where its signed copy goes.
let files = [];
// Folder for the signed copies of a batch; null means next to each original.
let folder = null;
// Save path picked for a single file; null means the default name.
let singleOutput = null;
let card = null;
let signing = false;

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
  } catch (e) {
    showError($("card-status"), e);
  }
  $("refresh").disabled = false;
  updateSignButton();
}

// --- Sign -----------------------------------------------------------------

function updateSignButton() {
  const pinOk = /^[0-9]{4,8}$/.test($("pin").value);
  const ready = files.length > 0 && card && !card.pin_blocked && pinOk && !signing;
  $("sign-button").disabled = !ready;
  $("sign-button").textContent = files.length > 1 ? `Firmar ${files.length} PDFs` : "Firmar";
}

async function updateOutputs() {
  for (const f of files) {
    f.output = await invoke("default_output", { input: f.input, folder });
  }
  if (files.length === 1 && singleOutput) files[0].output = singleOutput;
  renderFiles();
}

function renderFiles() {
  const list = $("file-list");
  list.hidden = files.length === 0;
  list.replaceChildren(
    ...files.map((f) =>
      el(
        "li",
        {},
        el("span", { textContent: baseName(f.input), title: f.input }),
        el("button", {
          type: "button",
          className: "link",
          textContent: "Quitar",
          disabled: signing,
          onclick: () => removeFile(f.input),
        }),
      ),
    ),
  );
  $("input-hint").textContent = files.length
    ? "Podés agregar más o arrastrarlos acá"
    : "o arrastralos a esta ventana";
  $("pick-input").textContent = files.length ? "Agregar PDFs…" : "Elegir PDFs…";
  $("output-row").hidden = files.length === 0;
  if (files.length === 1) {
    $("output-label").textContent = "Se guarda como";
    $("output-name").textContent = baseName(files[0].output);
    $("reset-output").hidden = true;
  } else if (files.length > 1) {
    $("output-label").textContent = "Se guardan como …-firmado.pdf";
    $("output-name").textContent = folder ? `en ${baseName(folder)}` : "junto a cada original";
    $("reset-output").hidden = !folder;
  }
  updateSignButton();
}

async function addFiles(paths) {
  if (signing) return;
  const pdfs = paths.filter(isPdf);
  const skipped = paths.length - pdfs.length;
  for (const input of pdfs) {
    if (!files.some((f) => f.input === input)) files.push({ input, output: null });
  }
  if (files.length > 1) singleOutput = null;
  $("sign-result").className = skipped ? "bad" : "";
  $("sign-result").textContent = skipped
    ? skipped === 1
      ? "Se ignoró un archivo que no es PDF."
      : `Se ignoraron ${skipped} archivos que no son PDF.`
    : "";
  await updateOutputs();
}

async function removeFile(input) {
  files = files.filter((f) => f.input !== input);
  if (files.length <= 1) singleOutput = null;
  await updateOutputs();
}

async function pickInput() {
  const picked = await open({ multiple: true, filters: pdfFilter });
  if (!picked) return;
  await addFiles(Array.isArray(picked) ? picked : [picked]);
}

async function pickOutput() {
  if (files.length === 1) {
    const path = await save({ defaultPath: files[0].output, filters: pdfFilter });
    if (!path) return;
    singleOutput = path;
  } else {
    const dir = await open({ directory: true, defaultPath: folder ?? undefined });
    if (!dir) return;
    folder = dir;
  }
  await updateOutputs();
}

async function resetOutput() {
  folder = null;
  await updateOutputs();
}

async function sign(event) {
  event.preventDefault();
  const result = $("sign-result");
  const pin = $("pin").value;
  const batch = files.map(({ input, output }) => ({ input, output }));
  const working = $("use-tsa").checked ? "Firmando y pidiendo el sello de tiempo" : "Firmando";
  $("pin").value = "";
  signing = true;
  renderFiles();
  $("refresh").disabled = true;
  result.className = "muted";
  result.textContent = `${working}…`;
  const progress = new Channel();
  progress.onmessage = (i) => {
    if (batch.length > 1) result.textContent = `${working} ${i + 1} de ${batch.length}…`;
  };
  try {
    const outcomes = await invoke("sign", {
      request: {
        files: batch,
        pin,
        reason: $("reason").value,
        location: $("location").value,
        visible: $("visible").checked,
        tsa: $("use-tsa").checked ? $("tsa").value : null,
      },
      progress,
    });
    showOutcomes(outcomes);
    // Keep only what still needs signing, so it can be retried.
    const signed = new Set(outcomes.filter((o) => o.saved).map((o) => o.input));
    files = files.filter((f) => !signed.has(f.input));
    if (files.length <= 1) singleOutput = null;
  } catch (e) {
    showError(result, e, "No se pudo firmar: ");
  }
  signing = false;
  await updateOutputs();
  // The tries counter may have changed either way.
  await refreshCard();
listen("opened-files", takeOpenedFiles).then(takeOpenedFiles);
}

function showOutcomes(outcomes) {
  const result = $("sign-result");
  const failed = outcomes.filter((o) => o.error);
  if (outcomes.length === 1) {
    const [o] = outcomes;
    if (o.saved) {
      result.className = "ok";
      result.textContent = `Listo: ${o.saved}`;
    } else {
      showError(result, o.error);
    }
    return;
  }
  result.className = failed.length ? "bad" : "ok";
  result.replaceChildren(
    failed.length
      ? `Se firmaron ${outcomes.length - failed.length} de ${outcomes.length} PDFs.`
      : `Listo: se firmaron los ${outcomes.length} PDFs.`,
    el(
      "ul",
      { className: "results" },
      ...outcomes.map((o) => {
        const li = el("li");
        if (o.saved) {
          li.className = "ok";
          li.textContent = `✓ ${baseName(o.saved)}`;
        } else {
          showError(li, o.error);
          li.prepend(`✗ ${baseName(o.input)}: `);
        }
        return li;
      }),
    ),
  );
}

// --- Verify ---------------------------------------------------------------

async function pickVerify() {
  const path = await open({ multiple: false, filters: pdfFilter });
  if (path) await verifyPath(path);
}

async function verifyPath(path) {
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

// --- Files from outside: drag-and-drop and "Open with Gancho" -------------

const signTabShown = () => !$("sign").hidden;

function showDropOverlay(paths) {
  const pdfs = paths.filter(isPdf).length;
  $("drop-text").textContent = !pdfs
    ? "Solo se pueden usar archivos PDF"
    : signTabShown()
      ? pdfs === 1
        ? "Soltá el PDF para firmarlo"
        : `Soltá los ${pdfs} PDFs para firmarlos`
      : "Soltá el PDF para verificarlo";
  $("drop-overlay").hidden = false;
}

async function dropped(paths) {
  $("drop-overlay").hidden = true;
  const pdfs = paths.filter(isPdf);
  if (signTabShown()) {
    await addFiles(paths);
  } else if (pdfs.length) {
    await verifyPath(pdfs[0]);
  }
}

getCurrentWebview().onDragDropEvent(({ payload }) => {
  if (payload.type === "enter") showDropOverlay(payload.paths);
  else if (payload.type === "leave") $("drop-overlay").hidden = true;
  else if (payload.type === "drop") dropped(payload.paths);
});

// Files opened with Gancho from Finder or Explorer go to the signing list.
async function takeOpenedFiles() {
  const paths = await invoke("take_opened_files");
  if (!paths.length) return;
  showTab("sign");
  await addFiles(paths);
}

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
$("reset-output").addEventListener("click", resetOutput);
$("pick-verify").addEventListener("click", pickVerify);
$("pin").addEventListener("input", updateSignButton);
$("use-tsa").addEventListener("change", (e) => ($("tsa-row").hidden = !e.target.checked));
$("sign").addEventListener("submit", sign);

refreshCard();
listen("opened-files", takeOpenedFiles).then(takeOpenedFiles);
