import { expect, test, type Page } from "@playwright/test";
import type { AIRequest } from "../src/shared/api";
import { launchReconBot, readFixture, setWindowSize } from "./harness";


async function openCopilot(page: Page): Promise<void> {
  const action = page.locator(".ai-hub .primary-ai-action");
  await expect(action).toContainText(/Open chat|Explain report/);
  await action.click();
  await expect(page.locator(".ai-drawer")).toBeVisible();
}


async function send(page: Page, message: string): Promise<void> {
  const textarea = page.locator(".ai-input-row textarea");
  await textarea.fill(message);
  await page.locator('.ai-input-row button[type="submit"]').click();
  await expect(page.locator(".ai-input-row .danger-button")).toHaveCount(0);
}


function aiRequests(calls: Array<{ channel: string; payload?: unknown }>): AIRequest[] {
  return calls
    .filter((call) => call.channel === "ai:request" && (call.payload as AIRequest | undefined)?.action !== "status")
    .map((call) => call.payload as AIRequest);
}





test("literal instruction reaches the model and renders without an appended template", async ({}, testInfo) => {
  const harness = await launchReconBot(testInfo, "historical");
  try {
    await openCopilot(harness.page);
    await expect(harness.page.getByRole("button", { name: /hoca|öğretmen/i })).toHaveCount(0);
    await harness.page.getByRole("button", { name: "Summarize this report as a short operator briefing", exact: true }).click();
    await expect(harness.page.locator(".ai-input-row textarea")).toHaveValue("Summarize this report as a short operator briefing");
    await send(harness.page, "Sadece evet yaz.");

    await expect(harness.page.locator(".ai-message.user").last().locator(".ai-message-body")).toHaveText("Sadece evet yaz.");
    await expect(harness.page.locator(".ai-message.assistant").last().locator(".ai-message-body")).toHaveText("Evet");

    const fixture = await readFixture(harness.app);
    const request = aiRequests(fixture.calls).at(-1);
    expect(request?.user_message).toBe("Sadece evet yaz.");
    expect(request?.question).toBe("Sadece evet yaz.");
    expect(harness.errors).toEqual([]);
  } finally {
    await harness.close();
  }
});


test("single-finding Turkish request selects only the first finding", async ({}, testInfo) => {
  const harness = await launchReconBot(testInfo, "historical");
  try {
    await openCopilot(harness.page);
    await send(harness.page, "Ben sadece ilk bulguyu açıklamanı istedim. Bir de Türkçe açıkla.");
    const answer = harness.page.locator(".ai-message.assistant").last();
    await expect(answer).toContainText("Fanwei e-cology RCE");
    await expect(answer).not.toContainText("eYouMail");
    await expect(answer).not.toContainText("Header disclosure");

    const fixture = await readFixture(harness.app);
    const request = aiRequests(fixture.calls).at(-1);
    expect(request?.user_message).toBe("Ben sadece ilk bulguyu açıklamanı istedim. Bir de Türkçe açıkla.");
    expect(harness.errors).toEqual([]);
  } finally {
    await harness.close();
  }
});


test("eYouMail selection persists and four items remain an explanation format", async ({}, testInfo) => {
  const harness = await launchReconBot(testInfo, "historical");
  try {
    await setWindowSize(harness.app, 1440, 900);
    await openCopilot(harness.page);
    await send(harness.page, "İkinci bulgu olan eYouMail hakkında konuşalım. Kısaca açıkla.");
    await expect(harness.page.locator(".ai-message.assistant").last()).toContainText("eYouMail");

    await send(harness.page, "Hangi bulgu hakkında konuşuyorduk?");
    await expect(harness.page.locator(".ai-message.assistant").last()).toContainText("eYouMail Remote Code Execution");
    await expect(harness.page.locator(".ai-message.assistant").last()).not.toContainText("Fanwei");

    await send(harness.page, "Bunu tam 4 maddede anlat.");
    const four = await harness.page.locator(".ai-message.assistant").last().locator(".ai-message-body").innerText();
    const items = four.split(/\n+/).filter((line) => /^\d+[.)]\s+/.test(line));
    expect(items).toHaveLength(4);
    expect(items.every((line) => /eYouMail/i.test(line))).toBe(true);

    const fixture = await readFixture(harness.app);
    const requests = aiRequests(fixture.calls);
    expect(requests.at(-2)?.selected_finding_reference?.template_id).toBe("eyoumail-rce");
    expect(requests.at(-1)?.selected_finding_reference?.template_id).toBe("eyoumail-rce");
    const plans = fixture.calls.filter((call) => call.channel === "ai:plan").map((call) => call.payload as Record<string, unknown>);
    expect(plans.at(-1)?.answerIntent).toBe("finding_question");
    expect((plans.at(-1)?.responsePreferences as Record<string, unknown>).requested_item_count).toBe(4);
    expect(harness.errors).toEqual([]);
  } finally {
    await harness.close();
  }
});


test("false-positive and detail followups stay direct, natural, and on eYouMail", async ({}, testInfo) => {
  const harness = await launchReconBot(testInfo, "historical");
  try {
    await openCopilot(harness.page);
    await send(harness.page, "İkinci bulgu olan eYouMail hakkında konuşalım. Kısaca açıkla.");
    await send(harness.page, "False-positive olabilir mi? Kısa cevapla, başlık kullanma.");
    const direct = harness.page.locator(".ai-message.assistant").last().locator(".ai-message-body");
    await expect(direct).toContainText("eYouMail");
    await expect(direct).toContainText("false-positive");
    await expect(direct).not.toContainText(/Rapor Özeti|Run durumu|Sonraki Adım/);

    await send(harness.page, "Biraz daha ayrıntılı anlat.");
    await expect(harness.page.locator(".ai-message.assistant").last()).toContainText("eYouMail");

    const fixture = await readFixture(harness.app);
    const requests = aiRequests(fixture.calls);
    expect(requests.at(-1)?.contextProfile).toBe("continuation");
    expect(requests.at(-1)?.selected_finding_reference?.template_id).toBe("eyoumail-rce");
    expect(harness.errors).toEqual([]);
  } finally {
    await harness.close();
  }
});


test("raw provider content and displayed text are identical in Technical Details", async ({}, testInfo) => {
  const harness = await launchReconBot(testInfo, "historical");
  try {
    await openCopilot(harness.page);
    const question = "İkinci bulgu olan eYouMail hakkında konuşalım. Kısaca açıkla.";
    await send(harness.page, question);
    const rendered = (await harness.page.locator(".ai-message.assistant").last().locator(".ai-message-body").innerText()).trim();

    const details = harness.page.locator(".ai-technical-details");
    await details.locator("summary").click();
    await expect(details).toContainText(`exact_latest_user_message: ${question}`);
    const raw = (await details.getByTestId("ai-raw-provider-content").innerText()).trim();
    const diagnosticRendered = (await details.getByTestId("ai-rendered-response").innerText()).trim();
    expect(raw).toBe(rendered);
    expect(diagnosticRendered).toBe(rendered);
    const messages = JSON.parse(await details.getByTestId("ai-provider-messages").innerText()) as Array<{ role: string; content: string }>;
    expect(messages.at(-1)).toEqual({ role: "user", content: question });
    await expect(details).toContainText("provider_http_status: 200");
    await expect(details).toContainText("answer_source: model");
    await expect(details).toContainText("answer_repair_attempt_count: 0");
    await expect(details).toContainText(/local_fallback: no/i);
    expect(harness.errors).toEqual([]);
  } finally {
    await harness.close();
  }
});


test("provider technical failure preserves a retryable user message and creates no fallback bubble", async ({}, testInfo) => {
  const harness = await launchReconBot(testInfo, "historical");
  try {
    await openCopilot(harness.page);
    const assistantsBefore = await harness.page.locator(".ai-message.assistant").count();
    await send(harness.page, "[[TIMEOUT]] doğrudan soru");
    await expect(harness.page.locator(".ai-message.assistant")).toHaveCount(assistantsBefore);
    const error = harness.page.locator(".ai-message.error").last();
    await expect(error).toContainText("yanıt süresi doldu");
    await expect(error.getByRole("button", { name: "Try again" })).toBeVisible();
    await expect(error).not.toContainText("ReconBot yedek yanıtı");
    expect(harness.errors).toEqual([]);
  } finally {
    await harness.close();
  }
});


test("configured AI settings become the effective provider request where supported", async ({}, testInfo) => {
  const harness = await launchReconBot(testInfo, "historical");
  try {
    await openCopilot(harness.page);
    await send(harness.page, "Ayarların etkisini doğrula.");
    const fixture = await readFixture(harness.app);
    const provider = fixture.calls.filter((call) => call.channel === "ai:provider-payload").at(-1)?.payload as Record<string, unknown>;
    const pythonConfig = fixture.calls.filter((call) => call.channel === "ai:python-config").at(-1)?.payload as Record<string, unknown>;
    expect(provider.model).toBe(pythonConfig.model);
    expect(provider.temperature).toBe(pythonConfig.temperature);
    expect(provider.configuredTimeoutSec).toBe(pythonConfig.timeout);
    expect(provider.responseMode).toBe(pythonConfig.responseMode);
    expect(provider.maxContextChars).toBe(pythonConfig.maxContextChars);
    expect(Number(provider.max_tokens)).toBeLessThanOrEqual(Number(pythonConfig.maxOutputTokens));
    expect(harness.errors).toEqual([]);
  } finally {
    await harness.close();
  }
});


test("accepted send clears immediately and produces one owned model answer", async ({}, testInfo) => {
  const harness = await launchReconBot(testInfo);
  try {
    await openCopilot(harness.page);
    const textarea = harness.page.locator(".ai-input-row textarea");
    await textarea.fill("[[DELAY_SUCCESS]] tek gönderim");
    await harness.page.locator('.ai-input-row button[type="submit"]').click();
    await expect(textarea).toHaveValue("");
    await expect(harness.page.locator(".ai-message.user")).toHaveCount(1);
    await expect(harness.page.locator(".ai-request-status")).toContainText("Model is generating a response");
    await expect(harness.page.locator(".ai-input-row .danger-button")).toHaveCount(0);
    await expect(harness.page.locator(".ai-message.assistant")).toHaveCount(1);
    await expect(harness.page.locator(".ai-message.assistant")).toContainText("Gecikmeli fakat geçerli model yanıtı");
    expect(harness.errors).toEqual([]);
  } finally {
    await harness.close();
  }
});


test("secret-like content stays unchanged in chat, history and diagnostics", async ({}, testInfo) => {
  const harness = await launchReconBot(testInfo, "historical");
  try {
    await openCopilot(harness.page);
    const content = "[[PRESERVE_CONTENT]]\nAuthorization: Bearer DEMO_TOKEN\npassword=DEMO_PASSWORD\nCookie: sessionid=DEMO_SESSION";
    await send(harness.page, content);
    const rendered = await harness.page.locator(".ai-message.assistant").last().locator(".ai-message-body").innerText();
    expect(rendered).toBe(content);
    const details = harness.page.locator(".ai-technical-details");
    await details.locator("summary").click();
    expect(await details.getByTestId("ai-raw-provider-content").innerText()).toBe(content);
    expect(await details.getByTestId("ai-rendered-response").innerText()).toBe(content);
    const messages = JSON.parse(await details.getByTestId("ai-provider-messages").innerText());
    expect(messages.at(-1)).toEqual({ role: "user", content });
    await expect(details).not.toContainText("secret-redacted");
    await send(harness.page, "Sadece evet yaz.");
    const fixture = await readFixture(harness.app);
    const history = aiRequests(fixture.calls).at(-1)?.conversation_history;
    expect(history?.filter((row) => row.content === content).map((row) => row.role)).toEqual(["user", "assistant"]);
    expect(harness.errors).toEqual([]);
  } finally {
    await harness.close();
  }
});
