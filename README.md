# yarforge

> **Work in Progress** — yarforge is actively under development. Expect missing features, rough edges, and breaking changes.

A command-line tool that automatically generates [YARA](https://virustotal.github.io/yara/) signature rules from PE (Portable Executable) files by extracting meaningful ASCII strings and filtering out noise (and more to come in the future).

---

## How It Works

yarforge parses a PE binary, extracts candidate ASCII strings, filters out low-value strings, and writes a ready-to-use `.yar` rule file into a `signatures/` directory.

### Pipeline

1. **Load PE** — The target binary is loaded via [`pe-lib`](https://github.com/NtProtectVirtualMemory/PE-Library).
2. **Extract Strings** — ASCII strings of length ≥ 6 are pulled from the image.
3. **Filter** — Strings are compared against several layers:
   - Prefix-based exclusion (section names, MSVC-mangled names, common runtime DLL names)
   - Import table cross-reference — any string matching a known imported function name is dropped
   - A large static blocklist covering MSVC runtime error messages, CRT/heap diagnostics, standard C++ exception strings, errno descriptions, and common runtime noise
4. **PDB Prompt** — If a `.pdb` path string is found, the user is asked interactively whether to include it.
5. **Serialize** — The collected strings and metadata are written out as a `.yar` rule file.

### Output Format

Generated rules follow this structure:

```yara
rule target_binary {
    meta:
        description = "yarforge generated this!"
        author      = "crim"
        reference   = "https://github.com/NtProtectVirtualMemory/yarforge"
        date        = "2025-01-01"
        hash        = ""

    strings:
        $s0 = "SomeString" fullword ascii
        $s1 = "AnotherString" fullword ascii

    condition:
        true
}
```

Rule names are derived from the input filename, sanitized to be valid YARA identifiers (lowercase alphanumeric, underscores, no leading digit, no consecutive underscores).

---

## Current Limitations (WIP)

yarforge is still in early development. The following areas are incomplete or placeholder:

- **`condition` block is always `true`** — No real condition logic is generated yet. Future versions will build meaningful conditions (e.g. `any of them`, PE header checks, minimum string matches).
- **`hash` meta field is empty** — The file hash is not yet computed and inserted automatically.
- **Windows-only** — Path handling and directory creation use Windows-style backslashes (`signatures\`). Cross-platform support is not yet implemented.
- **No wide-string support** — Only ASCII strings are extracted; Unicode/wide strings are not yet handled.
- **No confidence scoring or deduplication** — All surviving strings are included equally with no ranking or duplicate removal.
- **No import-based condition hints** — Import table data is used for filtering only; it could also inform condition generation (e.g. detecting specific API patterns).
- **All strings are hardcoded as `fullword ascii`** — No per-string modifier exists yet. Future versions will use appropriate modifiers (e.g. `wide`, `nocase`, `ascii wide`) based on context rather than applying `fullword ascii` universally.
---

## Dependencies

- [`pe-lib`](https://github.com/NtProtectVirtualMemory/PE-Library) — PE parsing (bundled)
- C++17 or later
- MSVC (recommended; `localtime_s` and `scanf_s` are used)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE.txt) file for details.

---

*Generated rules are a starting point — always review and refine before operational use.*
