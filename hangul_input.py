"""Small two-set Korean keyboard composer for browser text fields."""

INITIAL = "ㄱㄲㄴㄷㄸㄹㅁㅂㅃㅅㅆㅇㅈㅉㅊㅋㅌㅍㅎ"
MEDIAL = "ㅏㅐㅑㅒㅓㅔㅕㅖㅗㅘㅙㅚㅛㅜㅝㅞㅟㅠㅡㅢㅣ"
FINAL = " ㄱㄲㄳㄴㄵㄶㄷㄹㄺㄻㄼㄽㄾㄿㅀㅁㅂㅄㅅㅆㅇㅈㅊㅋㅌㅍㅎ"

KEYS = dict(zip(
    "rsefaqtdwczxvgkoi jpu h y n b m l".replace(" ", ""),
    "ㄱㄴㄷㄹㅁㅂㅅㅇㅈㅊㅋㅌㅍㅎㅏㅐㅑㅓㅔㅕㅗㅛㅜㅠㅡㅣ",
))
KEYS.update({"R": "ㄲ", "E": "ㄸ", "Q": "ㅃ", "T": "ㅆ", "W": "ㅉ",
             "O": "ㅒ", "P": "ㅖ"})
VOWELS = {"ㅏ", "ㅐ", "ㅑ", "ㅒ", "ㅓ", "ㅔ", "ㅕ", "ㅖ", "ㅗ", "ㅘ", "ㅙ",
          "ㅚ", "ㅛ", "ㅜ", "ㅝ", "ㅞ", "ㅟ", "ㅠ", "ㅡ", "ㅢ", "ㅣ"}
VOWEL_PAIRS = {
    ("ㅗ", "ㅏ"): "ㅘ", ("ㅗ", "ㅐ"): "ㅙ", ("ㅗ", "ㅣ"): "ㅚ",
    ("ㅜ", "ㅓ"): "ㅝ", ("ㅜ", "ㅔ"): "ㅞ", ("ㅜ", "ㅣ"): "ㅟ",
    ("ㅡ", "ㅣ"): "ㅢ",
}
FINAL_PAIRS = {
    ("ㄱ", "ㅅ"): "ㄳ", ("ㄴ", "ㅈ"): "ㄵ", ("ㄴ", "ㅎ"): "ㄶ",
    ("ㄹ", "ㄱ"): "ㄺ", ("ㄹ", "ㅁ"): "ㄻ", ("ㄹ", "ㅂ"): "ㄼ",
    ("ㄹ", "ㅅ"): "ㄽ", ("ㄹ", "ㅌ"): "ㄾ", ("ㄹ", "ㅍ"): "ㄿ",
    ("ㄹ", "ㅎ"): "ㅀ", ("ㅂ", "ㅅ"): "ㅄ",
}
SPLIT_FINAL = {value: pair for pair, value in FINAL_PAIRS.items()}


def compose(keys):
    """Compose two-set key symbols into displayable Hangul."""
    out = []
    lead = vowel = tail = None

    def emit():
        nonlocal lead, vowel, tail
        if lead and vowel:
            out.append(chr(0xAC00 + (INITIAL.index(lead) * 21 +
                        MEDIAL.index(vowel)) * 28 + FINAL.index(tail or " ")))
        elif lead:
            out.append(lead)
        elif vowel:
            out.append(vowel)
        lead = vowel = tail = None

    for key in keys:
        jamo = KEYS.get(key, KEYS.get(key.lower()))
        if jamo is None:
            emit()
            out.append(key)
            continue
        if jamo in VOWELS:
            if tail:
                if tail in SPLIT_FINAL:
                    first, second = SPLIT_FINAL[tail]
                else:
                    first, second = None, tail
                tail = first
                emit()
                lead, vowel = second, jamo
            elif vowel:
                combined = VOWEL_PAIRS.get((vowel, jamo))
                if combined:
                    vowel = combined
                else:
                    emit()
                    vowel = jamo
            else:
                vowel = jamo
        elif vowel:
            if lead is None:
                emit()
                lead = jamo
            elif tail:
                combined = FINAL_PAIRS.get((tail, jamo))
                if combined:
                    tail = combined
                else:
                    emit()
                    lead = jamo
            elif jamo in FINAL:
                tail = jamo
            else:
                emit()
                lead = jamo
        elif lead:
            emit()
            lead = jamo
        else:
            lead = jamo
    emit()
    return "".join(out)


class HangulComposer:
    def __init__(self):
        self.keys = ""
        self.rendered = ""

    def commit(self):
        self.keys = self.rendered = ""

    def update(self, key=None, backspace=False):
        if backspace:
            if not self.keys:
                return None
            self.keys = self.keys[:-1]
        elif key is not None:
            self.keys += key
        else:
            return None
        new = compose(self.keys)
        prefix = 0
        while (prefix < len(self.rendered) and prefix < len(new)
               and self.rendered[prefix] == new[prefix]):
            prefix += 1
        delete = len(self.rendered) - prefix
        insert = new[prefix:]
        self.rendered = new
        if not self.keys:
            self.commit()
        return delete, insert
