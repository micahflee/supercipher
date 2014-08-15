import json, locale

strings = {}

def load_strings(supercipher_dir, default="en"):
    global strings
    translated = json.loads(open('{0}/strings.json'.format(supercipher_dir)).read())
    strings = translated[default]
    lc, enc = locale.getdefaultlocale()
    if lc:
        lang = lc[:2]
        if lang in translated:
            # if a string doesn't exist, fallback to English
            for key in translated[default]:
                if key in translated[lang]:
                    strings[key] = translated[lang][key]
    return strings

def translated(k):
    return strings[k].encode("utf-8")

_ = translated
