import yaml


def load_config(path: str):
    with open(path) as f:
        return yaml.load(f)
