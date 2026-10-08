import uiMessages from "../src/renderer/lib/messages.json";
import { expect, test, type Locator, type Page } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { launchReconBot, setWindowSize } from "./harness";

const runLive = process.env.RECONBOT_RUN_LIVE_LM === "1";
const liveResponseTimeoutMs = 330_000;

type ProviderMessage = { role: string; content: string };
type TurnEvidence = {
  label: string;
  user: string;
  providerMessages: ProviderMessage[];
  rawProviderContent: string;
  renderedResponse: string;
  visibleResponse: string;
  semanticVisibleResponse: string;
  technical: Record<string, string>;
};

function aiSection(page: Page): Locator {
  return page.locator(".settings-section").filter({ has: page.getByRole("heading", { name: "Operator Copilot" }) }).first();
}

function control(section: Locator, label: string): Locator {
  return section.locator("label").filter({ has: section.page().getByText(uiMessages.find((entry) => entry.includes(label))?.[0] || label, { exact: true }) }).first().locator("input, select").first();
}

async function setValue(section: Locator, label: string, value: string): Promise<void> {
  const item = control(section, label);
  if (await item.evaluate((node) => node instanceof HTMLSelectElement)) await item.selectOption(value);
  else {
    await item.fill(value);
    await item.blur();
  }
}

function normalizeVisible(value: string): string {
  return value.replace(/\r\n?/g, "\n").trim();
}

function parseTechnical(text: string): Record<string, string> {
  const values: Record<string, string> = {};
  for (const match of text.matchAll(/^([a-z][a-z0-9_]+):\s*(.*)$/gm)) values[match[1]] = match[2].trim();
  return values;
}

function meaningfulListItems(answer: string): string[] {
  const items = answer.split(/\n+/).flatMap((line) => {
    const match = /^(\s*)(?:[-*•]|(?:\*\*)?\d+[.)](?:\*\*)?)\s+\S/.exec(line);
    return match ? [{ line, indent: match[1].replace(/\t/g, "    ").length }] : [];
  });
  // Four main items may contain supporting sublists; those are not extra main items.
  const topLevelIndent = Math.min(...items.map((item) => item.indent));
  return items.filter((item) => item.indent === topLevelIndent).map((item) => item.line);
}

async function sendAndCapture(page: Page, label: string, user: string): Promise<TurnEvidence> {
  const assistantCount = await page.locator(".ai-message.assistant").count();
  const errorCount = await page.locator(".ai-message.error").count();
  const textarea = page.locator(".ai-input-row textarea");
  await textarea.fill(user);
  await page.locator('.ai-input-row button[type="submit"]').click();
  await expect(textarea).toHaveValue("");
  await expect.poll(async () => ({
    assistants: await page.locator(".ai-message.assistant").count(),
    errors: await page.locator(".ai-message.error").count(),
  }), { timeout: liveResponseTimeoutMs, intervals: [500, 1000, 2000] }).not.toEqual({ assistants: assistantCount, errors: errorCount });
  if (await page.locator(".ai-message.error").count() > errorCount) {
    const message = await page.locator(".ai-message.error").last().innerText();
    const details = page.locator(".ai-technical-details");
    if (await details.isVisible()) {
      if (!(await details.evaluate((node) => (node as HTMLDetailsElement).open))) await details.locator("summary").click();
      const evidenceDir = path.resolve(__dirname, "../test-results/live-lmstudio");
      fs.mkdirSync(evidenceDir, { recursive: true });
      fs.writeFileSync(path.join(evidenceDir, `failure-${label}.json`), JSON.stringify({
        user, message, technical: await details.innerText(),
        rawProviderContent: await details.getByTestId("ai-raw-provider-content").innerText().catch(() => ""),
        providerMessages: await details.getByTestId("ai-provider-messages").innerText().catch(() => ""),
      }, null, 2));
    }
    throw new Error(`Live LM request failed for ${JSON.stringify(user)}: ${message}`);
  }

  const body = page.locator(".ai-message.assistant").last().locator(".ai-message-body");
  const visibleResponse = normalizeVisible(await body.innerText());
  const semanticVisibleResponse = normalizeVisible(await body.evaluate((node) => {
    const clone = node.cloneNode(true) as HTMLElement;
    for (const anchor of clone.querySelectorAll("a")) anchor.textContent = anchor.getAttribute("href") || anchor.textContent;
    return clone.textContent || "";
  }));
  const details = page.locator(".ai-technical-details");
  if (!(await details.evaluate((node) => (node as HTMLDetailsElement).open))) await details.locator("summary").click();
  await expect(details).toContainText("provider_http_status: 200");
  const technical = parseTechnical(await details.innerText());
  const providerMessages = JSON.parse(await details.getByTestId("ai-provider-messages").innerText()) as ProviderMessage[];
  const rawProviderContent = await details.getByTestId("ai-raw-provider-content").innerText();
  const renderedResponse = await details.getByTestId("ai-rendered-response").innerText();
  await details.locator("summary").click();

  expect(technical.exact_latest_user_message).toBe(user);
  expect(technical.provider_http_status).toBe("200");
  expect(["model", "repaired_model"]).toContain(technical.answer_source);
  expect(technical.answer_repair_attempt_count).toBe(technical.answer_source === "repaired_model" ? "1" : "0");
  expect(technical.local_fallback.toLowerCase()).toBe("no");

  expect(providerMessages.at(-1)).toEqual({ role: "user", content: user });
  expect(normalizeVisible(rawProviderContent)).toBe(normalizeVisible(renderedResponse));
  expect(normalizeVisible(rawProviderContent)).toBe(semanticVisibleResponse);

  return { label, user, providerMessages, rawProviderContent, renderedResponse, visibleResponse, semanticVisibleResponse, technical };
}

test.describe("real Electron + live LM Studio thin-pipeline acceptance", () => {
  test.skip(!runLive, "Set RECONBOT_RUN_LIVE_LM=1 to run against the loaded local LM Studio model.");

  test("human operator conversation records evidence for semantic review", async ({}, testInfo) => {
    test.setTimeout(30 * 60_000);
    const harness = await launchReconBot(testInfo, "historical", { liveAi: true });
    const evidenceDir = path.resolve(__dirname, "../test-results/live-lmstudio");
    fs.mkdirSync(evidenceDir, { recursive: true });
    const transcript: TurnEvidence[] = [];
    const model = process.env.RECONBOT_LIVE_TEST_MODEL || "mistralai/mistral-7b-instruct-v0.3";
    try {
      await setWindowSize(harness.app, 1440, 900);
      await harness.page.getByRole("button", { name: /Settings/i }).click();
      const settings = aiSection(harness.page);
      await setValue(settings, "Base URL", "http://127.0.0.1:1234/v1");
      await setValue(settings, "Endpoint modelleri", model);
      await setValue(settings, "Temperature", "0.3");
      await setValue(settings, "Timeout", "300");
      await setValue(settings, "Response mode", process.env.RECONBOT_LIVE_RESPONSE_MODE || "adaptive");
      await setValue(settings, "Max output tokens", process.env.RECONBOT_LIVE_OUTPUT_TOKENS || "2400");
      await settings.getByRole("button", { name: "Test connection" }).click();
      await expect(settings.locator(".ai-settings-status")).toContainText(/Connection successful|Bağlantı başarılı/, { timeout: 30_000 });
      await harness.page.locator(".ai-hub .primary-ai-action").click();
      await harness.page.getByRole("button", { name: "New chat" }).click();
      const questions = [
        "Bu raporu ilk kez açtım. Türkçe, normal bir sohbet gibi anlat: neye bakıyorum ve değerlendirmeye nereden başlamalıyım? Kısa tut.",
        "Kritik Nuclei eşleşmesi görünce sistem kesin ele geçirilmiş mi diyeyim? Gerçek açık ile false positive'i nasıl ayırırım?",
        "İkinci bulgu olan eYouMail hakkında konuşalım. Bu ne yapabilir, hangi kanıt elimizde var, hangi şeyleri henüz bilmiyoruz?",
        "Peki buradan nasıl ilerleyeyim? Az önce konuştuğumuz bulgu için yapacağım ilk üç kontrolü söyle, yeni bir bulgu uydurma.",
        "Bir de CVE tam olarak ne oluyor? CVE-2017-5638 neyi etkiler ve ne yapabilir? Bu CVE bizim eYouMail bulgusuyla aynı mı? Emin değilsen belirt, Türkçe açıkla.",
        "Authentication testimde Possible successful login — verification required gördüm. Şifre kesin bulundu mu? Bunu nasıl doğrularım?",
        "SQLmap raporunda Payload yazan yerde id=1 AND 8367=8367 var. Burada hangi kısım payload, bu neyi gösteriyor? Veritabanının tamamını aldığım anlamına geliyor mu?"
      ];
      const selectedQuestions = process.env.RECONBOT_LIVE_QA_FOCUS === "critical" ? questions.slice(2)
        : process.env.RECONBOT_LIVE_QA_FOCUS === "verification" ? questions.slice(2, 4) : questions;
      for (const [index, user] of selectedQuestions.entries()) {
        transcript.push(await sendAndCapture(harness.page, `human-${index + 1}`, user));
        fs.writeFileSync(path.join(evidenceDir, "human-operator-conversation.json"), JSON.stringify({fixture:"historical", model, transcript}, null, 2));
      }
      await harness.page.screenshot({path:path.join(evidenceDir, "human-operator-conversation.png")});
      expect(harness.errors).toEqual([]);
    } finally {
      await harness.close();
    }
  });

  test("acceptance A-F preserves exact user text, finding memory, and raw provider content", async ({}, testInfo) => {
    test.setTimeout(30 * 60_000);
    const harness = await launchReconBot(testInfo, "historical", { liveAi: true });
    const evidenceDir = path.resolve(__dirname, "../test-results/live-lmstudio");
    fs.mkdirSync(evidenceDir, { recursive: true });
    const transcript: TurnEvidence[] = [];
    const save = (): void => {
      fs.writeFileSync(
        path.join(evidenceDir, "thin-model-first-acceptance.json"),
        JSON.stringify({ model: "mistralai/mistral-7b-instruct-v0.3", transcript }, null, 2),
      );
    };

    try {
      await setWindowSize(harness.app, 1440, 900);
      await harness.page.getByRole("button", { name: /Settings/i }).click();
      const settings = aiSection(harness.page);
      await expect(settings).toBeVisible();
      await setValue(settings, "Base URL", "http://127.0.0.1:1234/v1");
      await setValue(settings, "Endpoint modelleri", "mistralai/mistral-7b-instruct-v0.3");
      await setValue(settings, "Temperature", "0.73");
      await setValue(settings, "Timeout", "300");
      await setValue(settings, "Max context chars", "7777");
      await setValue(settings, "Response mode", "adaptive");
      await setValue(settings, "Max output tokens", "24000");
      const reasoning = control(settings, "Thinking/Reasoning");
      if (await reasoning.isChecked()) await reasoning.locator("xpath=ancestor::label[1]").click();
      await expect(reasoning).not.toBeChecked();
      await settings.getByRole("button", { name: "Test connection" }).click();
      await expect(settings.locator(".ai-settings-status")).toContainText(/Connection successful|Bağlantı başarılı/, { timeout: 30_000 });

      await harness.page.locator(".ai-hub .primary-ai-action").click();
      await expect(harness.page.locator(".ai-drawer")).toBeVisible();

      const a = await sendAndCapture(harness.page, "A", "Sadece evet yaz.");
      transcript.push(a); save();
      expect(a.technical.answer_source).toBe("model");
      expect(a.technical.answer_repair_attempt_count).toBe("0");
      expect(a.visibleResponse).toMatch(/^evet[.!]?$/i);
      expect(a.visibleResponse).not.toMatch(/rapor|bulgu|durum|risk/i);

      await harness.page.getByRole("button", { name: "New chat" }).click();
      const b = await sendAndCapture(harness.page, "B", "Ben sadece ilk bulguyu açıklamanı istedim. Bir de Türkçe açıkla.");
      transcript.push(b); save();
      expect(b.visibleResponse).toMatch(/Fanwei/i);
      expect(b.visibleResponse).not.toMatch(/eYouMail|ShopXO|raporun tam metnini inceleyiniz/i);

      await harness.page.getByRole("button", { name: "New chat" }).click();
      const c1 = await sendAndCapture(harness.page, "C1", "İkinci bulgu olan eYouMail hakkında konuşalım. Kısaca açıkla.");
      transcript.push(c1); save();
      expect(c1.visibleResponse).toMatch(/eYouMail/i);
      expect(c1.visibleResponse).not.toMatch(/Fanwei/i);
      expect(c1.technical.selected_finding_title).toMatch(/eYouMail/i);

      const c2 = await sendAndCapture(harness.page, "C2", "Hangi bulgu hakkında konuşuyorduk?");
      transcript.push(c2); save();
      expect(c2.visibleResponse).toMatch(/eYouMail/i);
      expect(c2.visibleResponse).not.toMatch(/Fanwei/i);
      expect(c2.technical.selected_finding_title).toMatch(/eYouMail/i);

      const d = await sendAndCapture(harness.page, "D", "Bunu tam 4 maddede anlat.");
      transcript.push(d); save();
      expect(meaningfulListItems(d.visibleResponse)).toHaveLength(4);
      expect(d.technical.requested_format).toBe("list");
      expect(d.technical.requested_item_count).toBe("4");
      expect(d.technical.selected_finding_title).toMatch(/eYouMail/i);
      expect(d.visibleResponse).not.toMatch(/Fanwei|eylem planı|action plan/i);

      const e = await sendAndCapture(harness.page, "E", "False-positive olabilir mi? Kısa cevapla, başlık kullanma.");
      transcript.push(e); save();
      expect(e.technical.no_heading_requested.toLowerCase()).toBe("yes");
      expect(e.visibleResponse).not.toMatch(/(?:^|\n)\s*(?:#{1,6}\s+|(?:Durum|Özet|Sonuç|Değerlendirme)\s*:)/i);
      expect(e.visibleResponse).not.toMatch(/raporun tam metnini inceleyiniz/i);

      const f = await sendAndCapture(harness.page, "F", "Biraz daha ayrıntılı anlat.");
      transcript.push(f); save();
      expect(f.technical.selected_finding_title).toMatch(/eYouMail/i);
      expect(f.visibleResponse.length).toBeGreaterThan(e.visibleResponse.length);
      expect(f.visibleResponse).not.toMatch(/raporun tam metnini inceleyiniz|ReconBot yedek yanıtı/i);

      for (const turn of transcript) {
        expect(turn.technical.configured_max_output_tokens).toBe("24000");
        expect(Number(turn.technical.effective_max_output_tokens)).toBeLessThanOrEqual(24000);
        expect(turn.technical.configured_max_context_chars).toBe("7777");
        expect(Number(turn.technical.effective_injected_context_chars)).toBeLessThanOrEqual(7777);
        expect(turn.technical.provider_payload_fields).toContain("messages");
      }

      await harness.page.screenshot({ path: path.join(evidenceDir, "thin-model-first-acceptance.png") });
      expect(harness.errors).toEqual([]);
    } finally {
      save();
      await harness.close();
    }
  });
});
