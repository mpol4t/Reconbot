import type { ReconbotApi } from "../../shared/api";

declare global {
  interface Window {
    reconbot: ReconbotApi;
  }
}

export {};
