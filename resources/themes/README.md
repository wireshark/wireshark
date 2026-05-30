# Wireshark Themes

This directory contains color themes for Wireshark and Stratoshark.  Each
theme lives in its own subdirectory and is loaded by the `ThemeManager`
singleton at application startup.

## Directory layout

```
resources/themes/
    README.md               ← this file
    theme.schema.json       ← JSON Schema for theme.jsonc validation
    wireshark/              ← built-in Wireshark theme (Tango-based)
        theme.jsonc         ← color definitions (required)
        images/             ← theme-specific images (optional, future)
    stratoshark/            ← built-in Stratoshark theme (Cloud teal)
        theme.jsonc
    inverted/               ← diagnostic high-contrast theme
        theme.jsonc
    my-custom-theme/
        theme.jsonc
        images/
            logo.png
```

Each built-in theme directory **must** contain a `theme.jsonc` file.  It
**may** contain an `images/` subdirectory for theme-specific assets such
as background images or logos.

## Personal themes

In addition to the themes bundled in this directory (compiled into the
application as Qt resources), the application also loads user-supplied
themes from a personal themes directory:

| Platform | Path                                            |
|----------|-------------------------------------------------|
| Unix     | `$HOME/.local/lib/wireshark/themes/`            |
| Windows  | `%APPDATA%\Wireshark\themes\`                   |

For Stratoshark, substitute `stratoshark` / `Stratoshark` for `wireshark`
/ `Wireshark`.  The exact path is shown in the **About → Folders** dialog
as *Personal Themes*.

Personal themes use a **flat layout**: a single `.jsonc` file is dropped
directly into the directory — no per-theme subdirectory.  The filename
stem (the part before `.jsonc`) becomes the theme's internal name and
appears in the *Theme* dropdown under *Preferences → Appearance*.

```
$HOME/.local/lib/wireshark/themes/
    midnight.jsonc      ← internal name "midnight"
    high-contrast.jsonc ← internal name "high-contrast"
```

### Conflict resolution

If a personal theme uses the same name as a built-in theme (for example
`default.jsonc`), the built-in copy wins and the personal file is
skipped with a warning on stderr.  This is intentional: the application
falls back to the `default` theme if any other load fails, so allowing
`default` to be shadowed by a broken user file would risk leaving the
app with no valid color scheme.

### File format

Personal themes use exactly the same JSONC schema described below; the
only difference is the on-disk layout (single file vs. per-theme
directory).  Sidecar assets such as theme-local images are not supported
in the personal directory.

## Default theme per application flavor

The same Qt code drives both Wireshark and Stratoshark.  Which theme is
loaded out-of-the-box is decided at runtime by
`ThemeManager::defaultThemeName()`:

| Flavor                           | Default theme directory |
|----------------------------------|-------------------------|
| Stratoshark                      | `stratoshark/`          |
| Wireshark (and any other flavor) | `wireshark/`            |

The check is phrased as "wireshark unless stratoshark", so any future
flavor that doesn't ship its own theme directory inherits the
Wireshark theme automatically.  When the user's selected theme is
missing or fails to parse, `loadTheme()` retries with the flavor
default — so on a working build the application always ends up with a
usable color scheme.  See `ui/qt/utils/theme_manager.{h,cpp}` for the
exact resolution order.

Older builds wrote the literal `"default"` into `recent_common` as the
saved theme name; `ThemeManager::resolveThemeName()` silently migrates
that sentinel to the current flavor's default so existing user state
is preserved across the upgrade.

## File format: JSONC

Theme files use **JSONC** — standard JSON with C-style comments (`//`
line comments and `/* */` block comments).  The ThemeManager strips
comments before parsing with `QJsonDocument`, so no additional library
is needed.

## Theme file structure

```jsonc
{
    "meta": {
        "name": "My Theme",
        "version": 1,
        "description": "A short description shown in the preferences dialog.",
        "author": "Your Name"
    },

    "colors": {
        "section-name": {
            "token-name": { "light": "#rrggbb", "dark": "#rrggbb" }
        }
    }
}
```

A JSON Schema is provided at `theme.schema.json` for validation.
Editors that support JSON Schema (VS Code, IntelliJ, etc.) can use it
for autocompletion and error checking by adding a `$schema` reference
or configuring the schema association in editor settings.

### Top-level fields

| Field   | Type   | Required | Description |
|---------|--------|----------|-------------|
| `meta`  | object | yes      | Theme metadata (see below) |
| `colors`| object | yes      | Nested color definitions |

### `meta` — Theme metadata

| Field         | Type   | Required | Description |
|---------------|--------|----------|-------------|
| `name`        | string | yes      | Display name shown in preferences |
| `version`     | int    | yes      | Schema version, currently `1` |
| `description` | string | no       | One-line description |
| `author`      | string | no       | Theme author or organization |

### Color values

Each color token is an object with `"light"` and `"dark"` keys.
Accepted formats:

| Format                  | Example                    | Notes |
|-------------------------|----------------------------|-------|
| `#rrggbb`               | `"#2c6fb5"`                | Opaque hex |
| `#rrggbbaa`             | `"#2c6fb580"`              | Hex with alpha |
| `rgba(r, g, b, a)`      | `"rgba(76,175,80,51)"`     | CSS-style, alpha 0-255 (QSS convention) |

### Token naming in QSS

Nested keys are joined with dots to form the QSS token name, prefixed
and suffixed with `@`:

```jsonc
// In theme.jsonc:
"header": {
    "gradient-start": { "light": "#1e3a5f", "dark": "#0f1b30" }
}
```

```css
/* In a .qss file: */
#welcomeHeader {
    background: qlineargradient(
        stop:0 @header.gradient-start@,
        stop:1 @header.gradient-end@
    );
}
```

The ThemeManager resolves `@header.gradient-start@` to `#1e3a5f` (light)
or `#0f1b30` (dark) depending on the current appearance.

## Color sections reference

The default theme defines the following sections.  Custom themes should
provide values for all tokens to ensure complete coverage; any missing
token falls back to the default theme's value.

### `text` — Global text colors

| Token            | Purpose |
|------------------|---------|
| `primary`        | Primary content text |
| `muted`          | Secondary labels, file sizes, metadata |
| `on-dark`        | Text on dark gradient backgrounds (always white) |
| `on-dark-muted`  | De-emphasized text on dark backgrounds (50% white) |

### `accent` — Global accent colors

| Token    | Purpose |
|----------|---------|
| `blue`   | Wireshark brand blue, links, interactive highlights |
| `green`  | Success/update contexts, pulsing dot, download button |
| `orange` | Development badge, warning accent |

### `content` — Content area backgrounds

| Token           | Purpose |
|-----------------|---------|
| `bg`            | Main content area background |
| `border`        | Dividers, card borders, separators |
| `hover-bg`      | Row hover in file lists, interface lists |
| `selected-bg`   | Selected row background |
| `selected-text`  | Selected row text |
| `sidebar-bg`    | Learn card and sidebar backgrounds |

### `header` — Welcome page header bar

| Token            | Purpose |
|------------------|---------|
| `gradient-start` | Left/top stop of the blue gradient |
| `gradient-end`   | Right/bottom stop of the blue gradient |

### `update` — Update notification bar

| Token                | Purpose |
|----------------------|---------|
| `gradient-start`     | Left stop of the green gradient |
| `gradient-end`       | Right stop of the green gradient |
| `border`             | Bottom border of the update bar |
| `text`               | Primary update message text |
| `text-highlight`     | Bold version name within the message |
| `link`               | "Release Notes" link color |
| `link-hover`         | Link hover state |
| `link-pressed`       | Link pressed state |
| `btn-bg`             | "Download Update" button background |
| `btn-hover`          | Button hover |
| `btn-pressed`        | Button pressed |
| `btn-disabled-bg`    | Button disabled background |
| `btn-disabled-text`  | Button disabled text |
| `dismiss-hover-bg`   | Dismiss "x" hover background |
| `dismiss-pressed-bg` | Dismiss "x" pressed background |

### `section` — Section headers (Open, Capture, Learn)

| Token          | Purpose |
|----------------|---------|
| `header`       | Default text color for section titles |
| `header-hover` | Hover color for clickable section titles |

### `expert` — Expert info severity colors

| Token        | Purpose |
|--------------|---------|
| `comment`    | Green — Comment severity |
| `chat`       | Light blue — Chat severity |
| `note`       | Bright turquoise — Note severity |
| `warn`       | Yellow — Warning severity |
| `error`      | Pale red — Error severity |
| `foreground` | Text color on expert info backgrounds |

These colors originated in the GTK+ era and currently have no
dark-specific variants.  The `foreground` value (`#000000`) will need
adjustment for dark mode in a future iteration.

### `proto` — Protocol tree

| Token    | Purpose |
|----------|---------|
| `hidden` | Color for hidden protocol items when display is enabled |

### `status` — Status bar and warnings

| Token        | Purpose |
|--------------|---------|
| `warning-bg` | Warning background (status bar, time shift dialog) |

### `json` — JSON syntax highlighting

| Token       | Purpose |
|-------------|---------|
| `key`       | JSON object keys |
| `string`    | String values |
| `primitive` | Numbers, booleans, null |

### `graph` — Graph colors (1-14)

Rotating color cycle for I/O graphs, TCP stream graphs, LTE RLC
graphs, and RTP player scatter plots.  Slots 1-7 are saturated,
8-14 are pastel.  All derived from the Tango palette.

### `sequence` — Sequence diagram colors (1-10)

Rotating pastel backgrounds for flow/sequence diagrams.  Inherited
from GTK+ `graph_analysis.c`.  Currently identical in light and dark.

## Creating a custom theme

1. Copy one of the built-in themes to a new directory name (the
   Wireshark theme is the most complete starting point; copy
   `stratoshark/` instead if your custom theme should keep the
   Stratoshark surface tinting):
   ```
   cp -r resources/themes/wireshark resources/themes/my-theme
   ```

2. Edit `my-theme/theme.jsonc`:
   - Change `"name"` to your theme's display name
   - Adjust any colors you want to customize
   - Add images to `my-theme/images/` if desired

3. Missing tokens fall back to the default theme, so you only need to
   override the colors you want to change.

4. Place the directory in your personal configuration directory under
   `themes/` and select it in Edit -> Preferences -> Appearance.

## Relationship to Qt palette

The theme file defines colors for Wireshark-specific UI elements.  The
standard Qt palette roles (`base`, `text`, `window`, `highlight`, etc.)
remain OS-provided by default.  Stylesheet files may still use
`palette(base)`, `palette(text)`, etc. for structural colors that should
follow the platform convention.

A future extension may allow themes to override palette roles via an
optional `"palette"` section, enabling full visual control without
modifying system settings.
