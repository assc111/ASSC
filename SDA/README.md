# SDA

SDA is a skill dependency analysis tool. It analyzes agent skill files and extracts package dependencies, skill dependencies, and external services into a machine-readable SkillBOM JSON file.

## Usage

Run SDA from the `ASSC` directory:

```bash
cd /path/to/ASSC
python -m SDA generate -i /path/to/SKILL.md -o output.skillbom.json
```

The input can be a single `SKILL.md` file or a directory containing skill files.

To resolve skill dependencies with an existing SkillBOM database, pass `--skill-db`:

```bash
python -m SDA generate \
  -i /path/to/SKILL.md \
  -o output.skillbom.json \
  --skill-db /path/to/skillbom-db
```

Use `-` as the output path to print the result to stdout:

```bash
python -m SDA generate -i /path/to/SKILL.md -o -
```
