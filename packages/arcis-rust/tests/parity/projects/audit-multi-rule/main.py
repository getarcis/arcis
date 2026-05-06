import yaml
import pickle


def parse(path: str):
    with open(path) as f:
        return yaml.load(f)


def deserialize(blob: bytes):
    return pickle.loads(blob)


def evaluate(expr: str):
    return eval(expr)
