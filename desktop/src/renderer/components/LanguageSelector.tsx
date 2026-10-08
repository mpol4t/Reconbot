import { Languages } from "lucide-react";
import { setLanguage, useLanguage, type Language } from "../lib/i18n";

export default function LanguageSelector(): JSX.Element {
  const language = useLanguage();
  return (
    <label className="language-selector">
      <Languages size={15} aria-hidden="true" />
      <span>{language === "tr" ? "Arayüz dili" : "Interface language"}</span>
      <select aria-label={language === "tr" ? "Arayüz dili" : "Interface language"} value={language}
        onChange={(event) => setLanguage(event.target.value as Language)}>
        <option value="en">English</option>
        <option value="tr">Türkçe</option>
      </select>
    </label>
  );
}
