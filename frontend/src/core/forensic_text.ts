const named_code_points = new Map<number, string>([
  [0x00, "NULL"],
  [0x07, "BELL"],
  [0x08, "BACKSPACE"],
  [0x09, "TAB"],
  [0x0a, "LINE FEED"],
  [0x0d, "CARRIAGE RETURN"],
  [0x1b, "ESCAPE"],
  [0x7f, "DELETE"],
  [0x061c, "ARABIC LETTER MARK"],
  [0x200e, "LEFT-TO-RIGHT MARK"],
  [0x200f, "RIGHT-TO-LEFT MARK"],
  [0x202a, "LEFT-TO-RIGHT EMBEDDING"],
  [0x202b, "RIGHT-TO-LEFT EMBEDDING"],
  [0x202c, "POP DIRECTIONAL FORMATTING"],
  [0x202d, "LEFT-TO-RIGHT OVERRIDE"],
  [0x202e, "RIGHT-TO-LEFT OVERRIDE"],
  [0x2066, "LEFT-TO-RIGHT ISOLATE"],
  [0x2067, "RIGHT-TO-LEFT ISOLATE"],
  [0x2068, "FIRST STRONG ISOLATE"],
  [0x2069, "POP DIRECTIONAL ISOLATE"],
]);

function should_escape(code_point: number): boolean {
  return (
    code_point < 0x20 ||
    (code_point >= 0x7f && code_point <= 0x9f) ||
    named_code_points.has(code_point)
  );
}

export function render_forensic_text(value: string): string {
  return Array.from(value, (character) => {
    const code_point = character.codePointAt(0);
    if (code_point === undefined || !should_escape(code_point)) return character;
    const hexadecimal = code_point.toString(16).toUpperCase().padStart(4, "0");
    const name = named_code_points.get(code_point) ?? "CONTROL";
    return `⟦U+${hexadecimal} ${name}⟧`;
  }).join("");
}

export function render_forensic_value(value: unknown): string {
  if (value === null) return "null";
  if (value === undefined) return "unavailable";
  if (typeof value === "string") return render_forensic_text(value);
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return render_forensic_text(JSON.stringify(value, null, 2));
}
