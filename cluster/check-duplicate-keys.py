"""Fail on duplicate mapping keys in the rendered chart.

Helm does not catch this. `helm lint` and `helm template` both render a
document with a repeated key perfectly happily -- the last value simply
wins -- so a template edit that inserts a field next to an identical one
looks completely clean locally and in CI.

Flux does catch it, at apply time, with:

    yaml: unmarshal errors: line 63: mapping key "readOnly" already
    defined at line 62

which fails the HelmRelease and leaves the cluster on the previous
revision. That happened: a volumeMount inserted between a mount and its
own `readOnly: true` orphaned that key onto the new mount -- creating the
duplicate AND silently dropping readOnly from the mount that had it.

Reads rendered YAML on stdin.
"""
import sys
import yaml


class Strict(yaml.SafeLoader):
    pass


def no_duplicates(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise ValueError(f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


Strict.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, no_duplicates)

failures = 0
for doc in sys.stdin.read().split("\n---\n"):
    source = next(
        (line.split(": ", 1)[1] for line in doc.split("\n") if line.startswith("# Source:")),
        "<unknown>",
    )
    try:
        yaml.load(doc, Strict)
    except ValueError as exc:
        print(f"ERROR: {source}: {exc}", file=sys.stderr)
        failures += 1
    except yaml.YAMLError:
        # Not our concern here -- helm-template already covers whether a
        # document is well-formed at all.
        pass

if failures:
    print(f"{failures} document(s) with duplicate keys -- Flux would reject these at apply time.", file=sys.stderr)
    sys.exit(1)
print("ok:   no duplicate mapping keys in the rendered chart")
