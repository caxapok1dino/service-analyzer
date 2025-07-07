import json

def json_save(object, filename):
    with open(filename, "w") as f:
        json.dump(object, f, indent=4)

def json_load(filename):
    with open(filename, "w") as f:
        data = json.load(f)

