# yagura — Python tool

Source for the YAGURA CLI. See the [project README](../README.md) for full docs.

## Dev install

```bash
cd tool
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,ai]"
yagura --help
```

## Run tests

```bash
pytest tests/ -v
```

## Lint

```bash
ruff check yagura/
black --check yagura/
```
