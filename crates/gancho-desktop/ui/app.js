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
  const useTsa = timeSource() === "tsa";
  const lt = $("lt").checked;
  result.textContent =
    useTsa || lt ? "Firmando y consultando por internet…" : "Firmando…";
  try {
    const signed = await invoke("sign", {
      request: {
        input,
        output,
        pin,
        reason: $("reason").value,
        location: $("location").value,
        visible: $("visible").checked,
        tsa: useTsa ? $("tsa").value : null,
        lt,
      },
    });
    result.className = "ok";
    result.replaceChildren(`Listo: ${signed.output}`);
    for (const n of signed.notes) result.append(el("div", { className: "muted", textContent: n }));
  } catch (e) {
    showError(result, e, "No se pudo firmar: ");
  }
  // The tries counter may have changed either way.
  await refreshCard();
}

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

function renderCheck(c, i, all) {
  const lines = [
    c.signer && `Firmante: ${c.signer}`,
    c.time && `Fecha: ${c.time}`,
    c.reason && `Motivo: ${c.reason}`,
    c.location && `Lugar: ${c.location}`,
  ].filter(Boolean);
  return el(
    "div",
    { className: "sig" },
    el("h3", {
      className: c.valid ? "ok" : "bad",
      textContent: `${c.valid ? "✓ Firma válida" : "✗ Firma no válida"} (${all.length > 1 ? `${i + 1} de ${all.length}, ` : ""}${c.field ?? `firma ${i + 1}`})`,
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
function timeSource() {
  return document.querySelector('input[name="time"]:checked').value;
}
for (const radio of document.querySelectorAll('input[name="time"]')) {
  radio.addEventListener("change", () => ($("tsa-row").hidden = timeSource() !== "tsa"));
}
$("sign").addEventListener("submit", sign);

refreshCard();
