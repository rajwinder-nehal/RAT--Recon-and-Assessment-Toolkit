from datetime import datetime

_results = {}

def add(module, data):
    _results[module] = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "data": data,
    }

def get(module):
    return _results.get(module)

def clear():
    _results.clear()