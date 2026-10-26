# Wireshark Themes

This directory contains color themes for Wireshark and Stratoshark.  Each
theme lives in its own subdirectory and is loaded by the `ThemeManager`
singleton at application startup.

## Directory layout

```
resources/themes/
    README.md               ← this file
    theme.schema.json       ← JSON Schema for theme.jsonc validation
    wireshark/              ← built-in Wireshark theme (classic Wireshark colors)
        theme.jsonc         ← color definitions (required)
        images/             ← theme-specific images (optional, future)
    stratoshark/            ← built-in Stratoshark theme (Cloud teal)
        theme.jsonc
    inverted/               ← diagnostic inverted-color theme
        theme.jsonc
    high-contrast/          ← high contrast theme (High ratio set)
        theme.jsonc
    protan-deutan/          ← color vision theme: protanopia & deuteranopia
        theme.jsonc
    tritan/                 ← color vision theme: tritanopia
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
    solarized.jsonc     ← internal name "solarized"
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

#### `filter` (optional) — filter tint and glyph colour overrides

Optional subkeys, each a `{light, dark}` pair:

| Key          | Purpose |
|--------------|---------|
| `valid`      | Background tint when the filter expression is valid |
| `invalid`    | Background tint when the filter expression is rejected |
| `deprecated` | Background tint when the filter uses a deprecated field |
| `busy`       | Background while a capture filter is being compiled off-thread |
| `busyText`   | Foreground for the busy state (mirrors QLineEdit placeholder fade) |
| `history`    | Resting tint of the recent-filters drop-down arrow |
| `bookmark`   | Bookmark glyph of the display filter; default `accent.info` |
| `bookmarkCapture` | Bookmark glyph of the capture filter; default `accent.success` |
| `bookmarkMatch` | Bookmark glyph when the current filter is saved; default `accent.warning` |
| `clear`      | Clear glyph on hover/press (neutral grey at rest); default `accent.error` |
| `apply`      | Apply arrow; default `accent.info` |

Omitted tint keys derive from `accent.success` / `accent.error` /
`accent.warning` / `palette.base` / `palette.text`; `history` derives
from `palette.mid`; the glyph keys default to the accent named in their
row.  Glyphs brighten slightly on hover and are kept at the icon contrast
ratio against the filter field.  Explicit values let
themes ship the historical GTK-era saturated dark green / dark red
look that alpha-tinting an accent can never reach.

The derived tints are 33 % of the accent mixed onto `palette.base`.

Other tokens derived from the palette when a theme does not pin them:

- Ignored and hidden packet text fade `palette.windowText` toward
  `palette.base` (50 % and 40 %), so they stay readable on any background.
- `muted` text is `palette.text` faded 40 % toward `palette.base`, raised to
  at least the readable text ratio against `palette.base`.
- The selection color of lists, the packet details tree, the bytes pane and
  the welcome header (`palette.highlight`) falls back to
  `packets.selection`, then `brand.primary`.  Links (`palette.link`) follow
  it, raised to at least the readable text ratio against `palette.base`.
- Selection text (`palette.highlightedText`, `packets.selectionText`,
  `packets.inactiveText`, `packets.markedText`), pinned or derived, is
  raised to at least the readable text ratio against its own background.
- The accent alias `HighlightColorOrange` (search match highlight) follows
  `accent.warning`.
- The text on the filter validity tints (`TextOnFilterValid`,
  `TextOnFilterInvalid`, `TextOnFilterDeprecated`) is the
  `contrastingText()` of the matching `filter` tint, black or white.
- Cards (the welcome page Learn card) use `CardBackground`:
  `palette.alternateBase` when the theme sets it, else `palette.base`, moved
  to at least the dark card surface ratio against `palette.base` in dark
  themes, and used unchanged in light themes, where the border sets the card
  apart from the page. Their border and the lines on them (`CardBorder`)
  start from the separator, moved to at least the divider ratio against the
  card. Section headers and the keyboard focus ring on the card are raised
  to at least the readable text ratio against it. In dark themes, links on
  the card are raised far enough that they read at the readable text ratio
  on the list hover fill computed on the card; where that is not possible,
  the fill is moved toward the card until they do. In light themes, links
  keep `palette.link`, raised only to the readable text ratio against the
  card if needed, and the hover fill is moved toward the card until they
  read at the large text ratio on it.
- Overlay cards (the startup progress card) use the lighter of
  `palette.base` and the card background, with their own border at the
  divider ratio. The progress fill is `brand.primary` raised to at least the
  non-text ratio against the track.
- JSON keys (`SyntaxKey`) use `palette.mid` raised to at least the readable
  text ratio against `palette.base`.
- The Learn card's Donate button is filled with `accent.error`, darkened
  until its white label reads at the readable text ratio (dark-mode accents
  become deeper); hover and pressed darken further. Changing `accent.error`
  therefore recolors that button.

#### `separator` (optional) — hairline divider colour

Single `{light, dark}` pair used for dividers between sections. When
omitted, derived as a 53 % mix of `palette.base` toward `palette.mid`,
raised to at least the divider ratio against `palette.base`; a pin is used
as written. Themes whose `palette.mid` doubles as muted text (e.g.
Stratoshark) should set this explicitly to a softer value.

### Top-level fields

| Field   | Type   | Required | Description |
|---------|--------|----------|-------------|
| `meta`  | object | yes      | Theme metadata (see below) |
| `colors`| object | yes      | Nested color definitions |
| `contrast` | string | no    | `standard` (default) or `high`; `high` forces the high-contrast ratios for this theme (see Contrast) |

### `meta` — Theme metadata

| Field         | Type   | Required | Description |
|---------------|--------|----------|-------------|
| `name`        | string | yes      | Display name shown in preferences |
| `version`     | int    | yes      | Schema version, currently `1` |
| `description` | string | no       | One-line description |
| `author`      | string | no       | Theme author or organization |
| `colorVision` | array  | no       | Deficiencies the theme targets (`protanopia`, `deuteranopia`, `tritanopia`); bundled themes that set it are checked by `test/suite_theme.py` for distinguishable semantic colors. Packet coloring rules are profile data and are not part of a theme. |

### Color values

Each color token is an object with `"light"` and `"dark"` keys.
Accepted formats:

| Format                  | Example                    | Notes |
|-------------------------|----------------------------|-------|
| `#rrggbb`               | `"#2c6fb5"`                | Opaque hex |
| `#rrggbbaa`             | `"#2c6fb580"`              | Hex with alpha |
| `rgba(r, g, b, a)`      | `"rgba(76,175,80,51)"`     | CSS-style, alpha 0-255 (QSS convention) |

### Token naming in QSS

Stylesheets reference theme colors as `wstheme(TokenName)`, where
`TokenName` is a `ThemeManager::ThemeToken` enum name (case-sensitive).
The loader replaces each occurrence with the resolved `#rrggbb` value for
the current appearance:

```css
#welcomeHeader {
    background-color: wstheme(HeaderBackground);
}
```

Many tokens are not keys in `theme.jsonc` but are derived at load time
from the theme's inputs, for example:

- `HeaderBackground`: the palette Highlight darkened 40 %, kept at least the
  distinct surface ratio from the window and at least the readable text
  ratio from its title text.
- `HeaderText` / `HeaderTextMuted`: the welcome header title and version
  colors (HighlightedText when it reads on the bar, else black or white;
  the version label faded toward the bar, at least the large text ratio).
- `UpdateBackground`: `accent.success` darkened 60 %.

### Contrast

Many colors are derived from the theme (see the bullets above) and are held
to minimum contrast ratios. Two ratio sets exist, *Standard* and *High*.
The named ratios below are what the derivation bullets refer to.

| Ratio | Standard | High |
|-------|----------|------|
| readable text | `4.5:1` | `7.0:1` |
| large text | `3.0:1` | `4.5:1` |
| non-text | `3.0:1` | `4.5:1` |
| divider | `1.6:1` | `3.0:1` |
| distinct surface | `1.5:1` | `3.0:1` |
| dark card surface | `1.25:1` | `1.6:1` |
| icon | `1.6:1` | `4.5:1` |

The top-level `"contrast"` field (`"standard"` or `"high"`, default
`"standard"`) lets a theme require the High set. The effective level is High
when the loaded theme declares `"contrast": "high"`, or the *Contrast*
preference (*Preferences → Appearance*) is *High*, or the preference is
*System* and the operating system reports a high-contrast setting. The
preference never rewrites the selected theme. Detecting the operating system
setting requires Wireshark built with Qt 6.10 or later; with older Qt
versions *System* behaves like *Standard*. Older versions of Wireshark ignore
the field and load the theme as a normal theme.

In High:

- Derived colors use the High column above; pinned colors are used as
  written unless a rule below moves them.
- Text on selection, hover, filter tints, expert severities, conversation
  colors, the welcome header and the update bar is lifted to the readable
  text ratio; when that is out of reach for the text, the fill moves instead.
- Ignored and hidden packet text, and the busy filter text, are lifted
  against their background.
- The selection hover fill is moved to the distinct surface ratio, and its
  text switches to black or white when the view text cannot reach the
  readable text ratio on it.
- Palette roles a theme cannot set (button, tooltip, placeholder text,
  shadow) come from theme tokens, never from the operating system's
  high-contrast colors.
- Button, combo box and line edit frames use the `FieldBorder` color with
  the Fusion style; the macOS and Windows 11 styles keep their native frames.

Two cases are unreachable at the High ratios and the readable text wins: the
welcome header bar in dark themes cannot be both the distinct surface ratio
from a near-black window and the readable text ratio from a white title (the
title wins, the bar has no border), and the Learn card buttons (white label at
the readable text ratio) stay closer than the distinct surface ratio to a dark
card.

## Color sections reference

The default theme defines the following sections.  Custom themes should
provide values for all tokens to ensure complete coverage; any missing
token falls back to the default theme's value.

### `text` — Global text colors

| Token             | Purpose |
|-------------------|---------|
| `primary`         | Primary content text |
| `muted`           | Secondary labels, file sizes, metadata |
| `HeaderText`      | Derived, see Token naming |
| `HeaderTextMuted` | Derived, see Token naming |

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
| `selected-bg`   | Selected row background |
| `selected-text`  | Selected row text |
| `sidebar-bg`    | Learn card and sidebar backgrounds |

### `header` — Welcome page header bar

| Token        | Purpose |
|--------------|---------|
| `background` | `HeaderBackground`, derived, see Token naming |

### `update` — Update notification bar

| Token                | Purpose |
|----------------------|---------|
| `background`         | `UpdateBackground`, derived, see Token naming |
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

The warning background is the `filter.deprecated` tint.

### `json` — JSON syntax highlighting

| Token       | Purpose |
|-------------|---------|
| `key`       | JSON object keys |
| `string`    | String values |
| `primitive` | Numbers, booleans, null |

### `graph` — Graph colors (1-14)

Rotating color cycle for I/O graphs, TCP stream graphs, LTE RLC
graphs, and RTP player scatter plots.  Slots 1-7 are saturated,
8-14 are pastel.

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
come from the operating system unless the theme's optional `palette`
section sets them; only the roles listed there replace the system
values (see `theme.schema.json` for the roles a theme can set).
Stylesheet files use `palette(base)`, `palette(text)`, etc. for
structural colors, so they follow the theme where it sets a role and
the platform convention otherwise.

On macOS, a theme that sets `palette.window` also paints the top
toolbars in the unified title and toolbar area in that color, with a
`separator` line below the last toolbar row.  The title bar stays the
native system color.  Themes without `palette.window` keep the
native toolbar look.
