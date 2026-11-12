# ASSC Reproducibility Package

This repository accompanies the paper *Agent Skill Supply Chains in the Wild: Dependency Structure and Security Patterns*. Agent Skill Supply Chains (ASSCs) represent dependencies among agent skills, software packages, and external services. The package provides the SDA analysis tool, the SKILL-DEP benchmark, and interoperability examples, with the skill dataset and generated SkillBOMs hosted on HuggingFace.

## Contents

| Directory | Contents |
| --- | --- |
| [`examples/`](examples/) | Interoperability examples: import/export with SIT and SDA. |
| [`SDA/`](SDA/) | The Skill Dependency Analyzer, which extracts dependencies and generates SkillBOM documents. |
| [`skill-dep_benchmark/`](skill-dep_benchmark/) | Human-annotated reference data for evaluating metadata extraction, direct dependencies, and multi-layer skill dependency graphs. |

## Interoperability Examples

[`examples/`](examples/) contains artifacts illustrating an import/export round-trip with SIT between SkillBOM, SBOM IR, and standard SBOM formats. The example focuses on the npm package `czg` and its package dependencies.

| File | Representation |
| --- | --- |
| [`cz-git.skillbom.json`](examples/cz-git.skillbom.json) | SkillBOM document. |
| [`npm-czg.middleware.json`](examples/npm-czg.middleware.json) | SIT intermediate representation. |
| [`npm-czg.cyclonedx.json`](examples/npm-czg.cyclonedx.json) | CycloneDX 1.6 document. |
| [`npm-czg.spdx.json`](examples/npm-czg.spdx.json) | SPDX 2.3 document. |

These files illustrate how package components and dependency relationships are represented across the formats.

## SDA: Skill Dependency Analyzer

SDA analyzes agent skill files to extract skill metadata, package dependencies, skill dependencies, and external services, and serializes the results as machine-readable SkillBOM JSON. It can resolve referenced skills using an existing SkillBOM database.

From the repository root, generate a SkillBOM with:

```bash
python -m SDA generate -i /path/to/SKILL.md -o output.skillbom.json
```

See the **[SDA README](SDA/README.md)** for usage instructions, including directory input, dependency resolution with `--skill-db`, and output to stdout.

## SKILL-DEP Benchmark

[`skill-dep_benchmark/`](skill-dep_benchmark/) contains the human-annotated reference data used to evaluate SDA in RQ1 of the paper. The benchmark has two parts:

- **Single-layer:** 500 skill documents for evaluating root-skill metadata and direct package, skill, and service-use dependencies.
- **Multi-layer:** the paper evaluates 100 root skills with dependency graphs of depths 3–5 to assess the recovery of multi-layer skill dependencies.

## Skill Dataset and SkillBOMs

The skill dataset and generated SkillBOMs are publicly available on **[HuggingFace: skillbom/ASSC](https://huggingface.co/datasets/skillbom/ASSC)**.

The paper's dataset was collected from a June 6, 2026 snapshot of the SkillsMP registry. It contains 1,434,046 successfully retrieved GitHub-backed skill records, retaining repository and path information and SHA-256 content hashes. SDA-generated SkillBOMs support the paper's analyses of dependency structure and security propagation in RQ2 and RQ3.
