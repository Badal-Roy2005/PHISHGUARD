/**
 * Popup controller.
 *
 * The popup only reads the active tab's URL after a user action. It does not
 * inspect page content, forms, cookies, or keystrokes. Rendering uses
 * `textContent` exclusively; backend strings are never parsed as HTML.
 */

import type { AssessmentData } from "./lib/assessment.ts";
import {
  parseAssessResponse,
  parseClearCacheResponse,
} from "./lib/messages.ts";
import { RequestGate } from "./lib/request-gate.ts";
import { sanitizeUrl, type UrlSanitizationError } from "./lib/url.ts";
import { buildAssessmentView, HEURISTIC_NOTICE } from "./lib/view.ts";

type NoticeTone = "loading" | "info" | "error";

function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (element === null) {
    throw new Error(`Missing popup element #${id}`);
  }
  return element as T;
}

const cachedBadge = byId<HTMLSpanElement>("cached-badge");
const pageUrl = byId<HTMLParagraphElement>("page-url");
const urlNote = byId<HTMLParagraphElement>("url-note");
const recheckButton = byId<HTMLButtonElement>("recheck");
const clearButton = byId<HTMLButtonElement>("clear");
const notice = byId<HTMLParagraphElement>("notice");
const result = byId<HTMLElement>("result");
const resultHeading = byId<HTMLHeadingElement>("result-heading");
const bandBadge = byId<HTMLSpanElement>("band-badge");
const score = byId<HTMLParagraphElement>("score");
const verdict = byId<HTMLParagraphElement>("verdict");
const likelihood = byId<HTMLElement>("likelihood");
const posture = byId<HTMLElement>("posture");
const reasons = byId<HTMLUListElement>("reasons");
const missingSection = byId<HTMLDivElement>("missing-section");
const missing = byId<HTMLUListElement>("missing");
const coverage = byId<HTMLParagraphElement>("coverage");
const disclaimer = byId<HTMLParagraphElement>("disclaimer");

const gate = new RequestGate();
let isLoading = false;
let loadingKey: string | null = null;
let lastKey: string | null = null;
let refreshSequence = 0;

disclaimer.textContent = HEURISTIC_NOTICE;

function setNotice(text: string, tone: NoticeTone): void {
  notice.textContent = text;
  notice.dataset.tone = tone;
}

function setList(element: HTMLUListElement, items: readonly string[]): void {
  element.replaceChildren();
  for (const item of items) {
    const entry = document.createElement("li");
    entry.textContent = item;
    element.append(entry);
  }
}

function showUrl(display: string, notes: readonly string[]): void {
  pageUrl.textContent = display;
  if (notes.length === 0) {
    urlNote.hidden = true;
    urlNote.textContent = "";
    return;
  }
  urlNote.hidden = false;
  urlNote.textContent = notes.join(" ");
}

function renderLoading(): void {
  result.hidden = true;
  cachedBadge.hidden = true;
  setNotice("Assessing this page with PHISHGUARD...", "loading");
}

function renderIneligible(reason: UrlSanitizationError): void {
  result.hidden = true;
  cachedBadge.hidden = true;
  setNotice(`${reason.message} This page was not assessed.`, "error");
}

function renderNoTab(): void {
  result.hidden = true;
  cachedBadge.hidden = true;
  pageUrl.textContent = "No eligible page";
  urlNote.hidden = true;
  urlNote.textContent = "";
  setNotice("Could not read an HTTP or HTTPS address for this tab. It was not assessed.", "error");
}

function renderUnavailable(message: string): void {
  result.hidden = true;
  cachedBadge.hidden = true;
  setNotice(`${message} The page was not confirmed safe.`, "error");
}

function renderAssessment(data: AssessmentData, cached: boolean): void {
  const view = buildAssessmentView(data);

  result.hidden = false;
  result.dataset.state = view.state;
  resultHeading.textContent = view.headline;
  bandBadge.textContent = view.bandLabel;
  bandBadge.dataset.state = view.state;
  score.textContent = view.score === null ? "No score" : `${view.score} / 100`;
  verdict.textContent = view.verdict;
  likelihood.textContent = view.likelihoodLabel;
  posture.textContent = view.postureLabel;
  setList(reasons, view.reasons);

  missingSection.hidden = view.missing.length === 0;
  setList(missing, view.missing);
  coverage.textContent = view.coverageLabel;
  disclaimer.textContent = view.heuristicNotice;
  cachedBadge.hidden = !cached;

  setNotice(
    view.partial
      ? "Assessment complete with incomplete coverage."
      : "Assessment complete.",
    view.state === "high_risk" ? "error" : "info",
  );
}

async function readActiveTabUrl(): Promise<{ url: string | null; failed: boolean }> {
  try {
    const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    const tab = tabs[0];
    const url = tab?.url;
    return { url: typeof url === "string" && url !== "" ? url : null, failed: false };
  } catch {
    return { url: null, failed: true };
  }
}

async function refresh(force: boolean): Promise<void> {
  const sequence = ++refreshSequence;
  const active = await readActiveTabUrl();
  if (sequence !== refreshSequence) {
    return;
  }

  if (active.failed) {
    gate.cancel();
    renderUnavailable("Could not read the active tab.");
    return;
  }
  if (active.url === null) {
    gate.cancel();
    renderNoTab();
    return;
  }

  const sanitized = sanitizeUrl(active.url);
  if (!sanitized.ok) {
    gate.cancel();
    pageUrl.textContent = "Unsupported page";
    urlNote.hidden = true;
    urlNote.textContent = "";
    renderIneligible(sanitized);
    return;
  }

  const notes: string[] = [];
  if (sanitized.removedCredentials) {
    notes.push("Embedded URL credentials were removed before assessment.");
  }
  if (sanitized.redactedParams.length > 0) {
    notes.push(
      `${sanitized.redactedParams.length} sensitive query parameter(s) were removed before assessment.`,
    );
  }
  if (sanitized.removedFragment) {
    notes.push("The URL fragment was removed before assessment.");
  }
  showUrl(sanitized.display, notes);

  if (!force && lastKey === sanitized.url && !isLoading) {
    return;
  }
  if (!force && isLoading && loadingKey === sanitized.url) {
    return;
  }

  const token = gate.begin(sanitized.url);
  isLoading = true;
  loadingKey = sanitized.url;
  renderLoading();

  try {
    const response = await chrome.runtime.sendMessage({
      type: "assess",
      url: sanitized.url,
      force,
    });
    if (!gate.isCurrent(token, sanitized.url)) {
      return;
    }

    const parsed = parseAssessResponse(response);
    if (parsed === null) {
      renderUnavailable("The extension worker returned an unexpected response.");
      return;
    }
    if (!parsed.ok) {
      renderUnavailable(parsed.error.message);
      return;
    }

    lastKey = sanitized.url;
    renderAssessment(parsed.data, parsed.cached);
  } catch {
    if (gate.isCurrent(token, sanitized.url)) {
      renderUnavailable(
        "The extension background worker is unavailable. Reopen the popup and try again.",
      );
    }
  } finally {
    if (gate.isCurrent(token, sanitized.url)) {
      isLoading = false;
      loadingKey = null;
    }
  }
}

recheckButton.addEventListener("click", () => {
  void refresh(true);
});

clearButton.addEventListener("click", () => {
  clearButton.disabled = true;
  void (async () => {
    try {
      const response = await chrome.runtime.sendMessage({ type: "clear-cache" });
      const parsed = parseClearCacheResponse(response);
      if (parsed === null || !parsed.ok) {
        setNotice("Could not clear the cached result.", "error");
        return;
      }

      refreshSequence += 1;
      gate.cancel();
      isLoading = false;
      loadingKey = null;
      lastKey = null;
      result.hidden = true;
      cachedBadge.hidden = true;
      setNotice("Cached result cleared. Use Recheck to assess this page again.", "info");
    } catch {
      setNotice("The extension background worker is unavailable. The cache was not cleared.", "error");
    } finally {
      clearButton.disabled = false;
    }
  })();
});

// The popup is opened by a user action and closes as soon as it loses focus, so
// there is no tab monitoring, polling, or background navigation hook. Every
// assessment follows either this initial read or an explicit button click.
void refresh(false);
