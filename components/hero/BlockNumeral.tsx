/**
 * A count as a block numeral: a 5 by 7 grid of square cells per digit, the
 * lit ones amber and the rest a faint matrix (app/globals.css .hp-digit).
 * Plain elements, final in the HTML, and still: nothing assembles or
 * dissolves. Decoration for the eye; the number itself is in the text
 * beside it and in the button's label.
 */

/** 5x7 glyphs, rows top to bottom, "1" a lit cell. */
export const BLOCK_GLYPHS: Record<string, string[]> = {
  "0": ["01110", "10001", "10001", "10001", "10001", "10001", "01110"],
  "1": ["00100", "01100", "00100", "00100", "00100", "00100", "01110"],
  "2": ["01110", "10001", "00001", "00010", "00100", "01000", "11111"],
  "3": ["11110", "00001", "00001", "01110", "00001", "00001", "11110"],
  "4": ["00010", "00110", "01010", "10010", "11111", "00010", "00010"],
  "5": ["11111", "10000", "11110", "00001", "00001", "10001", "01110"],
  "6": ["00110", "01000", "10000", "11110", "10001", "10001", "01110"],
  "7": ["11111", "00001", "00010", "00100", "01000", "01000", "01000"],
  "8": ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
  "9": ["01110", "10001", "10001", "01111", "00001", "00010", "01100"],
};

export function BlockNumeral({ value }: { value: number }) {
  const digits = String(Math.max(0, Math.round(value))).split("");
  return (
    <span aria-hidden data-numeral={digits.join("")} className="hp-numeral">
      {digits.map((d, k) => (
        <span key={k} className="hp-digit">
          {BLOCK_GLYPHS[d]!.flatMap((row, y) => row.split("").map((c, x) => <i key={`${y}-${x}`} className={c === "1" ? "x" : undefined} />))}
        </span>
      ))}
    </span>
  );
}
