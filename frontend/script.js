"use strict";

/* =========================================================
   HashFox — frontend logic
   Talks only to this app's own local backend (/api/*).
   No third-party requests. No eval. No innerHTML with
   user-controlled or API-controlled text.
   ========================================================= */

const SAMPLE_HASH = "8743b52063cd84097a65d1633f5c74f5";

// Presentation-only threshold for the web UI: candidates within this many
// confidence points of the top score are shown prominently by default.
// This never changes backend ranking or scoring -- it only controls how
// many cards render before the "weaker matches" disclosure. All tied
// top candidates are always included regardless of this number, since
// the comparison is against the top score, not a fixed card count.
const PROMINENT_CONFIDENCE_DELTA = 10;

const els = {
  quickNav: document.getElementById("quick-nav"),

  analyzeForm: document.getElementById("analyze-form"),
  hashInput: document.getElementById("hash-input"),
  analyzeBtn: document.getElementById("analyze-btn"),
  clearBtn: document.getElementById("clear-btn"),
  sampleBtn: document.getElementById("sample-btn"),
  loadingState: document.getElementById("loading-state"),
  errorState: document.getElementById("error-state"),

  resultsPanel: document.getElementById("results-panel"),
  summaryGrid: document.getElementById("summary-grid"),
  ambiguityWarning: document.getElementById("ambiguity-warning"),
  emptyState: document.getElementById("empty-state"),
  candidatesSection: document.getElementById("candidates-section"),
  candidatesHeading: document.getElementById("candidates-heading"),
  tieSummary: document.getElementById("tie-summary"),
  candidateList: document.getElementById("candidate-list"),
  weakerControls: document.getElementById("weaker-controls"),
  toggleWeakerBtn: document.getElementById("toggle-weaker-btn"),

  pentestPanel: document.getElementById("pentest-panel"),
  pentestForm: document.getElementById("pentest-form"),
  hashFileInput: document.getElementById("hash-file-input"),
  wordlistInput: document.getElementById("wordlist-input"),
  rulesInput: document.getElementById("rules-input"),
  maskInput: document.getElementById("mask-input"),
  pentestBtn: document.getElementById("pentest-btn"),
  pentestLoading: document.getElementById("pentest-loading"),
  pentestError: document.getElementById("pentest-error"),
  pentestResults: document.getElementById("pentest-results"),
  pentestWarning: document.getElementById("pentest-warning"),
  pentestTargets: document.getElementById("pentest-targets"),
  attackSequence: document.getElementById("attack-sequence"),
  nextSteps: document.getElementById("next-steps"),
  foxTip: document.getElementById("fox-tip"),

  toast: document.getElementById("toast"),

  candidateTemplate: document.getElementById("candidate-card-template"),
  targetTemplate: document.getElementById("target-panel-template"),
};

let lastAnalysis = null;
let toastTimer = null;
let showAllWeakerCandidates = false;

/* ---------------------------------------------------------
   Helpers
   --------------------------------------------------------- */

function setHidden(el, hidden) {
  if (hidden) {
    el.setAttribute("hidden", "");
  } else {
    el.removeAttribute("hidden");
  }
}

function clearChildren(el) {
  while (el.firstChild) {
    el.removeChild(el.firstChild);
  }
}

function showToast(message) {
  els.toast.textContent = message;
  setHidden(els.toast, false);
  // Force reflow so the transition re-triggers on rapid consecutive calls.
  void els.toast.offsetWidth;
  els.toast.classList.add("is-visible");
  if (toastTimer) {
    clearTimeout(toastTimer);
  }
  toastTimer = setTimeout(() => {
    els.toast.classList.remove("is-visible");
    setTimeout(() => setHidden(els.toast, true), 200);
  }, 2200);
}

async function copyToClipboard(text, button) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      // Fallback for non-secure contexts (e.g. plain http://localhost
      // is still considered secure by browsers, but keep a safety net).
      const helper = document.createElement("textarea");
      helper.value = text;
      helper.style.position = "fixed";
      helper.style.opacity = "0";
      document.body.appendChild(helper);
      helper.focus();
      helper.select();
      document.execCommand("copy");
      document.body.removeChild(helper);
    }
    showToast("Copied to clipboard");
    if (button) {
      flashCopiedState(button);
    }
  } catch (err) {
    showToast("Could not copy — select the text manually");
  }
}

function flashCopiedState(button) {
  const originalLabel = button.dataset.originalLabel || button.textContent;
  button.dataset.originalLabel = originalLabel;
  button.textContent = "Copied ✓";
  button.classList.add("is-copied");
  button.disabled = true;
  clearTimeout(button._copiedTimer);
  button._copiedTimer = setTimeout(() => {
    button.textContent = originalLabel;
    button.classList.remove("is-copied");
    button.disabled = false;
  }, 1600);
}

function summaryItem(label, value, mono) {
  const item = document.createElement("div");
  item.className = "summary-item";

  const dt = document.createElement("span");
  dt.className = "summary-label";
  dt.textContent = label;

  const dd = document.createElement("span");
  dd.className = mono ? "summary-value mono" : "summary-value";
  dd.textContent = value;

  item.appendChild(dt);
  item.appendChild(dd);
  return item;
}

function formatBool(value) {
  if (value === true) return "Yes";
  if (value === false) return "No";
  return "Unknown";
}

function formatOrDash(value) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

async function requestJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  let data = null;
  try {
    data = await response.json();
  } catch (err) {
    data = null;
  }

  if (!response.ok) {
    const message =
      (data && (data.detail || data.error)) ||
      `Request failed with status ${response.status}.`;
    const err = new Error(
      typeof message === "string" ? message : JSON.stringify(message)
    );
    err.status = response.status;
    throw err;
  }

  return data;
}

/* ---------------------------------------------------------
   Analyze flow
   --------------------------------------------------------- */

function renderSummary(result) {
  clearChildren(els.summaryGrid);
  els.summaryGrid.appendChild(
    summaryItem("Input hash", truncateForDisplay(result.original_input), true)
  );
  els.summaryGrid.appendChild(summaryItem("Length", String(result.input_length)));
  els.summaryGrid.appendChild(
    summaryItem("Candidates found", String(result.candidate_count))
  );
  els.summaryGrid.appendChild(
    summaryItem("Ambiguous", result.ambiguous ? "Yes" : "No")
  );
  els.summaryGrid.appendChild(
    summaryItem(
      "Manual verification",
      result.manual_verification_recommended ? "Recommended" : "Not required"
    )
  );
}

function truncateForDisplay(value) {
  if (!value) return "(empty)";
  if (value.length <= 80) return value;
  return value.slice(0, 40) + "…" + value.slice(-30);
}

function renderAmbiguityWarning(result) {
  if (result.ambiguous && result.ambiguity_message) {
    els.ambiguityWarning.textContent = result.ambiguity_message;
    setHidden(els.ambiguityWarning, false);
  } else {
    setHidden(els.ambiguityWarning, true);
  }
}

function fillList(ul, items) {
  clearChildren(ul);
  items.forEach((text) => {
    const li = document.createElement("li");
    li.textContent = text;
    ul.appendChild(li);
  });
}

function buildCandidateCard(candidate, isTop, ambiguous) {
  const node = els.candidateTemplate.content.cloneNode(true);
  const card = node.querySelector(".candidate-card");

  card.querySelector(".candidate-name").textContent = candidate.name || "Unknown format";

  const aliases = candidate.aliases || [];
  card.querySelector(".candidate-aliases").textContent = aliases.length
    ? "Also known as: " + aliases.join(", ")
    : "";

  const confidence = typeof candidate.confidence === "number" ? candidate.confidence : 0;
  card.querySelector(".confidence-value").textContent = confidence + "%";
  const ring = card.querySelector(".ring-value");
  const circumference = 2 * Math.PI * 27;
  const offset = circumference * (1 - confidence / 100);
  ring.style.strokeDasharray = String(circumference);
  ring.style.strokeDashoffset = String(offset);

  card.querySelector(".candidate-category").textContent = formatOrDash(candidate.category);
  card.querySelector(".candidate-hashcat-mode").textContent = formatOrDash(candidate.hashcat_mode);
  card.querySelector(".candidate-john-format").textContent = formatOrDash(candidate.john_format);
  card.querySelector(".candidate-security-level").textContent = formatOrDash(candidate.security_level);
  card.querySelector(".candidate-detection-quality").textContent = formatOrDash(candidate.detection_quality);

  const description = candidate.description;
  const descEl = card.querySelector(".candidate-description");
  if (description) {
    descEl.textContent = description;
  } else {
    descEl.remove();
  }

  const usageBlock = card.querySelector(".candidate-usage");
  const usage = candidate.common_usage || [];
  if (usage.length) {
    fillList(usageBlock.querySelector(".usage-list"), usage);
    setHidden(usageBlock, false);
  }

  const reasons = candidate.reasons || [];
  fillList(card.querySelector(".reasons-list"), reasons);

  if (isTop) {
    card.classList.add("is-top");
    if (ambiguous) {
      card.classList.add("is-uncertain");
    }
  }

  return node;
}

function countTiedTopCandidates(candidates) {
  if (!candidates.length) return 0;
  const topConfidence = candidates[0].confidence;
  return candidates.filter((c) => c.confidence === topConfidence).length;
}

function renderCandidates(result) {
  const candidates = result.candidates || [];
  showAllWeakerCandidates = false;

  if (!candidates.length) {
    setHidden(els.emptyState, false);
    setHidden(els.candidatesSection, true);
    return;
  }

  setHidden(els.emptyState, true);
  setHidden(els.candidatesSection, false);

  // Heading + tie summary: never imply the first card is "the" confirmed
  // answer when several share the same top score.
  const tieCount = countTiedTopCandidates(candidates);
  if (result.ambiguous) {
    els.candidatesHeading.textContent = "Top plausible matches";
    els.tieSummary.textContent =
      tieCount > 1
        ? `${tieCount} formats share the strongest structural match.`
        : "Multiple formats share a similar structural match.";
    setHidden(els.tieSummary, false);
  } else {
    els.candidatesHeading.textContent = "Possible matches";
    setHidden(els.tieSummary, true);
  }

  renderCandidateCards(result, candidates, tieCount);
}

function renderCandidateCards(result, candidates, tieCount) {
  const topConfidence = candidates[0].confidence;
  const prominent = candidates.filter(
    (c) => topConfidence - c.confidence <= PROMINENT_CONFIDENCE_DELTA
  );
  const weaker = candidates.slice(prominent.length);

  clearChildren(els.candidateList);

  const toRender = showAllWeakerCandidates ? candidates : prominent;
  toRender.forEach((candidate) => {
    // A card is only visually "top" if it's part of the tied-strongest
    // group -- ties always get equivalent emphasis, not just index 0.
    const isTop = candidate.confidence === topConfidence;
    const card = buildCandidateCard(candidate, isTop, result.ambiguous && tieCount > 1);
    els.candidateList.appendChild(card);
  });

  if (weaker.length > 0) {
    setHidden(els.weakerControls, false);
    els.toggleWeakerBtn.textContent = showAllWeakerCandidates
      ? "Hide weaker matches"
      : `Show ${weaker.length} weaker match${weaker.length === 1 ? "" : "es"}`;
  } else {
    setHidden(els.weakerControls, true);
  }
}

async function runAnalysis(hashValue) {
  setHidden(els.errorState, true);
  els.errorState.textContent = "";
  setHidden(els.loadingState, false);
  els.analyzeBtn.disabled = true;

  try {
    const result = await requestJson("/api/analyze", { hash: hashValue });
    lastAnalysis = result;
    renderSummary(result);
    renderAmbiguityWarning(result);
    renderCandidates(result);
    setHidden(els.resultsPanel, false);
    setHidden(els.pentestPanel, false);
    setHidden(els.pentestResults, true);
    setHidden(els.quickNav, false);
    els.resultsPanel.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) {
    lastAnalysis = null;
    setHidden(els.resultsPanel, true);
    setHidden(els.pentestPanel, true);
    setHidden(els.quickNav, true);
    els.errorState.textContent = describeError(err);
    setHidden(els.errorState, false);
  } finally {
    setHidden(els.loadingState, true);
    els.analyzeBtn.disabled = false;
  }
}

function describeError(err) {
  if (err && err.message) {
    return err.message;
  }
  return "Something went wrong talking to the local HashFox backend. Confirm the server is running.";
}

/* ---------------------------------------------------------
   Pentest flow
   --------------------------------------------------------- */

function buildTargetPanel(target) {
  const node = els.targetTemplate.content.cloneNode(true);

  node.querySelector(".target-name").textContent = target.name || "Unknown format";
  node.querySelector(".target-confidence").textContent =
    (typeof target.confidence === "number" ? target.confidence : "—") + "%";

  node.querySelector(".target-hashcat-mode").textContent = formatOrDash(target.hashcat_mode);
  node.querySelector(".target-john-format").textContent = formatOrDash(target.john_format);
  node.querySelector(".target-security-level").textContent = formatOrDash(target.security_level);

  const usage = target.common_usage || [];
  node.querySelector(".target-common-usage").textContent = usage.length
    ? usage.join(", ")
    : "—";

  const hashcat = target.hashcat_commands || {};
  let anyHashcatCommand = false;

  if (hashcat.dictionary) {
    const block = node.querySelector(".dictionary-block");
    block.querySelector(".dictionary-command").textContent = hashcat.dictionary;
    setHidden(block, false);
    anyHashcatCommand = true;
  }
  if (hashcat.rules) {
    const block = node.querySelector(".rules-block");
    block.querySelector(".rules-command").textContent = hashcat.rules;
    setHidden(block, false);
    anyHashcatCommand = true;
  }
  if (hashcat.mask) {
    const block = node.querySelector(".mask-block");
    block.querySelector(".mask-command").textContent = hashcat.mask;
    setHidden(block, false);
    anyHashcatCommand = true;
  }
  if (!anyHashcatCommand) {
    setHidden(node.querySelector(".hashcat-unavailable"), false);
  }

  if (target.john_command) {
    const block = node.querySelector(".john-block");
    block.querySelector(".john-command").textContent = target.john_command;
    setHidden(block, false);
  } else {
    const unavailable = node.querySelector(".john-unavailable");
    unavailable.textContent =
      target.john_command_unavailable_reason ||
      "Verified John the Ripper format unavailable.";
    setHidden(unavailable, false);
  }

  // Wire up copy buttons scoped to this panel instance.
  const article = node.querySelector(".target-panel");
  article.querySelectorAll("[data-copy-target]").forEach((btn) => {
    const kind = btn.getAttribute("data-copy-target");
    let text = null;
    if (kind === "dictionary") text = hashcat.dictionary;
    if (kind === "rules") text = hashcat.rules;
    if (kind === "mask") text = hashcat.mask;
    if (kind === "john") text = target.john_command;

    btn.addEventListener("click", () => {
      if (text) copyToClipboard(text, btn);
    });
  });

  return node;
}

async function runPentest() {
  if (!lastAnalysis) {
    return;
  }

  setHidden(els.pentestError, true);
  els.pentestError.textContent = "";
  setHidden(els.pentestLoading, false);
  els.pentestBtn.disabled = true;

  const payload = {
    hash: lastAnalysis.original_input,
    hash_file: els.hashFileInput.value.trim() || "hash.txt",
    wordlist: els.wordlistInput.value.trim() || "/usr/share/wordlists/rockyou.txt",
  };
  const rulesValue = els.rulesInput.value.trim();
  const maskValue = els.maskInput.value.trim();
  if (rulesValue) payload.rules_file = rulesValue;
  if (maskValue) payload.mask = maskValue;

  try {
    const assistance = await requestJson("/api/pentest", payload);
    renderPentestResults(assistance);
    setHidden(els.pentestResults, false);
  } catch (err) {
    setHidden(els.pentestResults, true);
    els.pentestError.textContent = describeError(err);
    setHidden(els.pentestError, false);
  } finally {
    setHidden(els.pentestLoading, true);
    els.pentestBtn.disabled = false;
  }
}

function renderPentestResults(assistance) {
  if (assistance.ambiguous && assistance.warning) {
    els.pentestWarning.textContent = assistance.warning;
    setHidden(els.pentestWarning, false);
  } else {
    setHidden(els.pentestWarning, true);
  }

  clearChildren(els.pentestTargets);
  (assistance.targets || []).forEach((target) => {
    els.pentestTargets.appendChild(buildTargetPanel(target));
  });
  if (!assistance.targets || !assistance.targets.length) {
    const empty = document.createElement("p");
    empty.className = "panel-hint";
    empty.textContent = "No plausible targets available for command preparation.";
    els.pentestTargets.appendChild(empty);
  }

  fillList(els.attackSequence, assistance.recommended_attack_sequence || []);
  fillList(els.nextSteps, assistance.next_steps || []);

  els.foxTip.textContent = assistance.fox_tip || "";
}

/* ---------------------------------------------------------
   Event wiring
   --------------------------------------------------------- */

els.analyzeForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const value = els.hashInput.value.trim();
  if (!value) {
    els.errorState.textContent = "Enter a hash to analyze.";
    setHidden(els.errorState, false);
    return;
  }
  runAnalysis(value);
});

els.hashInput.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    event.preventDefault();
    els.analyzeForm.requestSubmit();
  }
});

els.clearBtn.addEventListener("click", () => {
  els.hashInput.value = "";
  els.hashInput.focus();
  setHidden(els.errorState, true);
  setHidden(els.resultsPanel, true);
  setHidden(els.pentestPanel, true);
  setHidden(els.quickNav, true);
  lastAnalysis = null;
});

els.toggleWeakerBtn.addEventListener("click", () => {
  if (!lastAnalysis) return;
  showAllWeakerCandidates = !showAllWeakerCandidates;
  const candidates = lastAnalysis.candidates || [];
  const tieCount = countTiedTopCandidates(candidates);
  renderCandidateCards(lastAnalysis, candidates, tieCount);
});

els.sampleBtn.addEventListener("click", () => {
  els.hashInput.value = SAMPLE_HASH;
  els.hashInput.focus();
});

els.pentestForm.addEventListener("submit", (event) => {
  event.preventDefault();
  runPentest();
});
