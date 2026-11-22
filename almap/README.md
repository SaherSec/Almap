# almap/

The ALmap sources: the Goose program (`almap.goose`, `modules/`), the C layer (`c/`), the plugins (`plugins/`), the tests (`tests/`) and the tools (`tools/`).

See the top-level [README](../README.md) for what ALmap is, how to build and run it, and the plugin status; [docs/GUIDE.md](../docs/GUIDE.md) for the full guide; and [CHANGELOG.md](../CHANGELOG.md) for what changed in each release.

```sh
export GOOSE_STDLIB=/path/to/goose/stdlib
goose build almap.goose --cc gcc -o almap
bash tools/build_plugins.sh
bash tests/run_all.sh
```
