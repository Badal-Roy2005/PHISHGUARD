/**
 * Typed messages between the popup and the service worker.
 *
 * Incoming messages must come from this extension's own extension pages. There
 * are no content scripts, so `sender.id` plus an extension URL/origin is the
 * complete author check.
 */

import {
  isAssessmentData,
  isAssessmentFailure,
  type AssessmentData,
  type AssessmentFailure,
} from "./assessment.ts";

export interface AssessMessage {
  type: "assess";
  url: string;
  force: boolean;
}

export interface ClearCacheMessage {
  type: "clear-cache";
}

export type ExtensionMessage = AssessMessage | ClearCacheMessage;

export type AssessResponse =
  | { ok: true; cached: boolean; data: AssessmentData }
  | { ok: false; error: AssessmentFailure };

export type ClearCacheResponse =
  | { ok: true }
  | { ok: false; error: AssessmentFailure };

const MAX_INCOMING_URL_LENGTH = 8192;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

export function parseExtensionMessage(value: unknown): ExtensionMessage | null {
  if (!isRecord(value)) {
    return null;
  }
  if (value.type === "assess") {
    if (!hasOnlyKeys(value, ["type", "url", "force"])) {
      return null;
    }
    if (
      typeof value.url !== "string" ||
      value.url.length < 8 ||
      value.url.length > MAX_INCOMING_URL_LENGTH
    ) {
      return null;
    }
    if (value.force !== undefined && typeof value.force !== "boolean") {
      return null;
    }
    return { type: "assess", url: value.url, force: value.force === true };
  }
  if (value.type === "clear-cache") {
    if (!hasOnlyKeys(value, ["type"])) {
      return null;
    }
    return { type: "clear-cache" };
  }
  return null;
}

export interface SenderLike {
  id?: string;
  url?: string;
  origin?: string;
}

export function isTrustedSender(sender: SenderLike | undefined, extensionId: string): boolean {
  if (sender === undefined || extensionId === "") {
    return false;
  }
  if (sender.id !== extensionId) {
    return false;
  }
  const extensionOrigin = `chrome-extension://${extensionId}`;
  if (typeof sender.origin === "string" && sender.origin === extensionOrigin) {
    return true;
  }
  if (typeof sender.url === "string" && sender.url.startsWith(`${extensionOrigin}/`)) {
    return true;
  }
  return false;
}

export function parseAssessResponse(value: unknown): AssessResponse | null {
  if (!isRecord(value)) {
    return null;
  }
  if (value.ok === true) {
    if (typeof value.cached !== "boolean" || !isAssessmentData(value.data)) {
      return null;
    }
    return { ok: true, cached: value.cached, data: value.data };
  }
  if (value.ok === false) {
    if (!isAssessmentFailure(value.error)) {
      return null;
    }
    return { ok: false, error: value.error };
  }
  return null;
}

export function parseClearCacheResponse(value: unknown): ClearCacheResponse | null {
  if (!isRecord(value)) {
    return null;
  }
  if (value.ok === true) {
    return { ok: true };
  }
  if (value.ok === false && isAssessmentFailure(value.error)) {
    return { ok: false, error: value.error };
  }
  return null;
}
