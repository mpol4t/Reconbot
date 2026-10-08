import type { MouseEvent, ReactNode } from "react";

export type LinkifiedToken =
  | { type: "text"; text: string }
  | { type: "url"; url: string; label: string };

const URL_PATTERN = /\bhttps?:\/\/[^\s<>"'`{}|\\^]+/gi;
const TRAILING_PUNCTUATION_PATTERN = /[),.;:!?]+$/;

function splitTrailingPunctuation(value: string): { url: string; trailing: string } {
  const match = value.match(TRAILING_PUNCTUATION_PATTERN);
  if (!match) return { url: value, trailing: "" };
  return {
    url: value.slice(0, -match[0].length),
    trailing: match[0]
  };
}

function firstMeaningfulPathSegment(pathname: string): string {
  return pathname
    .split("/")
    .map((part) => part.trim())
    .filter(Boolean)
    .find((part) => !["api", "v1", "v2"].includes(part.toLowerCase())) || "";
}

export function shortUrlLabel(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl);
    const host = parsed.host || parsed.hostname;
    const firstSegment = firstMeaningfulPathSegment(parsed.pathname);
    if (!firstSegment) return host;
    const hasMorePath = parsed.pathname.split("/").filter(Boolean).length > 1;
    const suffix = hasMorePath || parsed.search ? "/..." : "";
    return `${host} › /${firstSegment}${suffix}`;
  } catch {
    return rawUrl.length > 64 ? `${rawUrl.slice(0, 61)}...` : rawUrl;
  }
}

export function tokenizeLinks(text: string): LinkifiedToken[] {
  const tokens: LinkifiedToken[] = [];
  let lastIndex = 0;
  for (const match of text.matchAll(URL_PATTERN)) {
    const rawMatch = match[0];
    const index = match.index ?? 0;
    const { url, trailing } = splitTrailingPunctuation(rawMatch);
    if (!url) continue;
    if (index > lastIndex) {
      tokens.push({ type: "text", text: text.slice(lastIndex, index) });
    }
    tokens.push({ type: "url", url, label: shortUrlLabel(url) });
    if (trailing) tokens.push({ type: "text", text: trailing });
    lastIndex = index + rawMatch.length;
  }
  if (lastIndex < text.length) {
    tokens.push({ type: "text", text: text.slice(lastIndex) });
  }
  return tokens.length ? tokens : [{ type: "text", text }];
}

export function LinkifiedText({
  text,
  onOpenUrl
}: {
  text: string;
  onOpenUrl?: (url: string) => void;
}): JSX.Element {
  const tokens = tokenizeLinks(text);
  const children: ReactNode[] = tokens.map((token, index) => {
    if (token.type === "text") return token.text;
    const onClick = (event: MouseEvent<HTMLAnchorElement>): void => {
      if (!onOpenUrl) return;
      event.preventDefault();
      onOpenUrl(token.url);
    };
    return (
      <a
        key={`${token.url}-${index}`}
        className="ai-link"
        href={token.url}
        title={token.url}
        rel="noreferrer"
        target="_blank"
        onClick={onClick}
      >
        {token.label}
      </a>
    );
  });
  return <>{children}</>;
}
