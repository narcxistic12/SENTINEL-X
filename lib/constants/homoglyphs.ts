// Map of non-Latin characters commonly used to spoof Latin letters in phishing domains
export const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic
  '\u0430': 'a', // Cyrillic Small Letter A
  '\u0441': 'c', // Cyrillic Small Letter Es -> c
  '\u0435': 'e', // Cyrillic Small Letter Ie -> e
  '\u0456': 'i', // Cyrillic Small Letter Byelorussian-Ukrainian I -> i
  '\u0458': 'j', // Cyrillic Small Letter Je -> j
  '\u043E': 'o', // Cyrillic Small Letter O -> o
  '\u0440': 'p', // Cyrillic Small Letter Er -> p
  '\u0455': 's', // Cyrillic Small Letter Dze -> s
  '\u0443': 'y', // Cyrillic Small Letter U -> y
  '\u0445': 'x', // Cyrillic Small Letter Ha -> x
  // Greek
  '\u03B1': 'a', // Greek Small Letter Alpha -> a
  '\u03B5': 'e', // Greek Small Letter Epsilon -> e
  '\u03B9': 'i', // Greek Small Letter Iota -> i
  '\u03BF': 'o', // Greek Small Letter Omicron -> o
  '\u03C1': 'p', // Greek Small Letter Rho -> p
  '\u03C5': 'u', // Greek Small Letter Upsilon -> u
  '\u03C7': 'x', // Greek Small Letter Chi -> x
};

export function detectHomoglyphs(str: string): { hasHomoglyphs: boolean; characters: string[] } {
  const found: string[] = [];
  for (const char of str) {
    if (HOMOGLYPH_MAP[char]) {
      found.push(`${char} (resembles Latin '${HOMOGLYPH_MAP[char]}')`);
    }
  }
  return {
    hasHomoglyphs: found.length > 0,
    characters: found,
  };
}
