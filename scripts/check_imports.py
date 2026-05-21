import json
import importlib.util

mods = {
    'customtkinter': importlib.util.find_spec('customtkinter') is not None,
    'requests': importlib.util.find_spec('requests') is not None,
    'docx': importlib.util.find_spec('docx') is not None,
}
print(json.dumps(mods))
