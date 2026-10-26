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
    solarized/              ← Solarized (Ethan Schoonover), light and dark
        theme.jsonc
    catppuccin-frappe/      ← Catppuccin Frappé, Latte for light
        theme.jsonc
    catppuccin-macchiato/   ← Catppuccin Macchiato, Latte for light
        theme.jsonc
    catppuccin-mocha/       ← Catppuccin Mocha, Latte for light
        theme.jsonc
    tokyo-night/            ← Tokyo Night, Tokyo Night Light for light
        theme.jsonc
    tokyo-night-storm/      ← Tokyo Night Storm, Tokyo Night Light for light
        theme.jsonc
    my-custom-theme/
        theme.jsonc
        images/
            logo.png
```

Each built-in theme directory **must** contain a `theme.jsonc` file.  It
**may** contain an `images/` subdirectory for theme-specific assets such
as background images or logos.  Every directory with a `theme.jsonc` is
compiled in (`add_bundled_themes()` in `cmake/modules/AddThemes.cmake`);
re-run CMake after adding one.

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
as *Personal Themes*; **Help → Personal Themes Folder** and the folder link
under the theme list of the Theme Designer open it.

Personal themes use a **flat layout**: a single `.jsonc` file is dropped
directly into the directory — no per-theme subdirectory.  The filename
stem (the part before `.jsonc`) becomes the theme's internal name and
appears in the *Theme* dropdown under *Preferences → Appearance*.

```
$HOME/.local/lib/wireshark/themes/
    midnight.jsonc      ← internal name "midnight"
    ocean.jsonc         ← internal name "ocean"
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

A theme is one JSONC object.  The sections sit at the top level of the
document (there is no wrapping `colors` object):

```jsonc
{
    "meta":   { "name": "My Theme", "version": 1,
                "description": "Shown in the preferences dialog.",
                "author": "Your Name" },
    "brand":  { "primary": { "light": "#1a73e8", "dark": "#8ab4f8" } },
    "accent": { "success": { "light": "#2e7d32", "dark": "#66bb6a" },
                "warning": { "light": "#ed6c02", "dark": "#ffa726" },
                "error":   { "light": "#d32f2f", "dark": "#f44336" },
                "info":    { "light": "#0288d1", "dark": "#29b6f6" } }
}
```

Only `meta`, `brand` and `accent` are required.  Every other section,
and every token inside a section, is optional.  **A token a theme omits
is derived, not copied from the default theme**: the application computes
it from `brand`, `accent` and `palette` (see "Derived colors" below).
Key names are matched case-insensitively; this document and the schema
use camelCase.  Unknown keys inside a known section are reported on
stderr and ignored; unknown top-level keys are ignored.  The optional
top-level `contrast` field (`standard`, the default, or `high`) makes the
theme use the high-contrast ratios (see "Contrast").

A JSON Schema is provided at `theme.schema.json` for validation.
Editors that support JSON Schema (VS Code, IntelliJ, etc.) can use it
for autocompletion and error checking by adding a `$schema` reference
or configuring the schema association in editor settings.

### `meta` — Theme metadata

| Field         | Type   | Required | Description |
|---------------|--------|----------|-------------|
| `name`        | string | yes      | Display name shown in preferences |
| `version`     | int    | yes      | Schema version, currently `1` |
| `description` | string | no       | One-line description |
| `author`      | string | no       | Theme author or organization |
| `colorVision` | array  | no       | Deficiencies the theme targets (`protanopia`, `deuteranopia`, `tritanopia`); bundled themes that set it are checked by `test/suite_theme.py` for distinguishable semantic colors. Packet coloring rules are profile data and are not part of a theme. |

### Color values

Each color token is an object with `"light"` and `"dark"` keys.  The
values are read by Qt's `QColor`:

| Format        | Example       | Notes |
|---------------|---------------|-------|
| `#rrggbb`     | `"#2c6fb5"`   | Opaque hex |
| `#aarrggbb`   | `"#802c6fb5"` | Hex with alpha; the alpha byte comes **first** |

`rgba(r, g, b, a)` is not understood by `QColor`; such a value is
rejected with a warning and treated as missing.  Use hex.  If only one
of `light` and `dark` is valid, the parser uses it for both and warns.

### Color sections reference

| Section | Keys | Purpose |
|---------|------|---------|
| `brand` (required) | `primary` | Visual identity: last fallback of the selection color, links, section header hover |
| `accent` (required) | `success`, `warning`, `error`, `info` | Update bar, filter validation, status indicators, expert fallbacks |
| `palette` | `window`, `windowText`, `base`, `text`, `alternateBase`, `mid`, `midlight`, `highlight`, `highlightedText`, `accent` | QPalette role overrides; only the roles given replace the system value |
| `expert` | `none`, `comment`, `chat`, `note`, `warn`, `error`, `foreground` | Expert-info row colors; `none` is the background of items without a severity, `foreground` the text on them |
| `packets` | `selection`, `selectionText`, `inactive`, `inactiveText`, `marked`, `markedText`, `ignored`, `ignoredText`, `hidden` | Packet-list and details state colors (background and matching text) |
| `conversation` | `client`, `clientText`, `server`, `serverText` | Follow Stream client and server colors |
| `filter` | `valid`, `invalid`, `deprecated`, `busy`, `busyText`, `history`, `bookmark`, `bookmarkCapture`, `bookmarkMatch`, `clear`, `apply` | Filter field tints and inline glyph colors (details below) |
| `separator` | one color pair | Hairline divider between cards and sections |
| `graphs` | array of color pairs | Rotating color cycle for graphs and diagrams |
| `fonts` | `regular`, `monospace` | Font hints, see "Fonts" |

`syntax` and `images` are accepted by the schema but reserved: the
application does not read them yet.

#### `expert`

When a severity is omitted its color is a translucent tint of the matching
`accent` value.

#### `packets`

For each state the unsuffixed key is the row background tint and the
`*Text` key is the foreground; `hidden` is text only.  An omitted `*Text`
key is derived with `contrastingText()` against its background.  The
selection, inactive and marked text, pinned or derived, is raised to a
readable contrast against its own background.  When `ignored` is omitted
the row keeps its normal background.

#### `conversation`

Omitted backgrounds derive from `accent.error` (client) and
`brand.primary` (server) tinted onto `palette.base`; omitted `*Text`
keys are darkened (light mode) or lightened (dark mode) versions of the
same colors.

#### `filter`

| Key               | Purpose |
|-------------------|---------|
| `valid`           | Background tint when the filter expression is valid |
| `invalid`         | Background tint when the filter expression is rejected |
| `deprecated`      | Background tint when the filter uses a deprecated field |
| `busy`            | Background while a capture filter is being compiled off-thread |
| `busyText`        | Foreground for the busy state |
| `history`         | Resting tint of the recent-filters drop-down arrow |
| `bookmark`        | Bookmark glyph of the display filter; default `accent.info` |
| `bookmarkCapture` | Bookmark glyph of the capture filter; default `accent.success` |
| `bookmarkMatch`   | Bookmark glyph when the current filter is saved; default `accent.warning` |
| `clear`           | Clear glyph on hover/press (neutral grey at rest); default `accent.error` |
| `apply`           | Apply arrow; default `accent.info` |

Omitted tint keys derive from `accent.success` / `accent.error` /
`accent.warning` / `palette.base` / `palette.text`; `history` derives
from `palette.mid`; the glyph keys default to the accent named in their
row.  Glyphs brighten slightly on hover and are kept at the icon contrast
ratio against the filter field.  Explicit values let themes ship a saturated dark green / dark red look
that alpha-tinting an accent can never reach.

#### `separator`

When omitted, derived by mixing `palette.base` toward
`palette.mid`, raised to at least the divider ratio against
`palette.base`; a pin is used as written.  Themes whose `palette.mid` doubles as muted text should
set it explicitly to a softer value.

#### `graphs`

Any number of color pairs; there is no backfill from the default theme.

#### Fonts

`fonts.regular` and `fonts.monospace` each take an optional `family`
(string) and `size` (integer points).  What is omitted falls back to the
platform default.  The monospace font chosen on the **Fonts** preferences
page (`gui.fonts.qt.font_name`) overrides the theme's monospace font when
it is set.

### Derived colors

These groups are not settable from a theme file; they are computed from
the colors above whenever a token is not given:

- The selection color (`palette.highlight`) of lists, the packet details
  tree, the bytes pane and the welcome header falls back to
  `packets.selection`, then `brand.primary`.  Its text
  (`palette.highlightedText`) falls back to `packets.selectionText` when
  the selection color is `packets.selection`, else black or white, and is
  raised to a readable contrast against it.
  Hover fills are derived from the selection color.
- The welcome page header (`HeaderBackground`, `HeaderText`,
  `HeaderTextMuted`) is a flat, darkened shade of the selection color with
  readable title and version text.  The update bar (`UpdateBackground`) is a
  flat, darkened `accent.success`.  Section headers and field borders follow
  `brand`, `accent` and the palette.
- `muted` text is `palette.text` faded toward `palette.base`, then raised to
  a readable contrast against `palette.base`.  Links (`palette.link`)
  follow the selection color and are raised the same way.
- Text on accent and filter backgrounds (`TextOnSuccess`,
  `TextOnFilterValid`, ...) is the `contrastingText()` of its
  background, black or white.
- Diff line tints (`DiffAdded`, `DiffChanged`, `DiffRemoved`) and notice
  banners (`NoticeInfo`, `NoticeError` and their `...Border`) tint
  `palette.base` toward `accent.success`, `accent.info` or `accent.error`.
- Ignored and hidden packet text fade `palette.windowText` toward
  `palette.base`.  The busy filter text (`filter.busyText`) fades
  `palette.text` toward `palette.base`; pinned or derived, it is raised to
  the large text ratio against `filter.busy`.
- The search-match highlight follows `accent.warning`.
- Cards (the welcome page Learn card) use `CardBackground`:
  `palette.alternateBase` when the theme sets it, else `palette.base`, moved
  to at least the dark card surface ratio against `palette.base` in dark
  themes, and used unchanged in light themes, where the border sets the card
  apart from the page. Their border and the lines on them (`CardBorder`)
  start from the separator, moved to at least the divider ratio against the
  card. Section headers, links and the keyboard focus ring on the card are
  raised to a readable contrast against it.
- Overlay cards (the startup progress card) use the lighter of
  `palette.base` and the card background, with their own border at the
  divider ratio. The progress fill is `brand.primary` raised to at least the
  non-text ratio against the track.
- JSON keys (`SyntaxKey`) use `palette.mid` raised to a readable contrast
  against `palette.base`.
- The Learn card's Donate button is filled with `accent.error`, darkened
  until its white label is readable; changing `accent.error` therefore
  recolors that button.

The exact rule of every derived color is the text the Theme Designer shows
in the detail of its Derived row. That text is written next to the
computation in `ThemeTokenHandler::deriveAll()`
(`ui/qt/utils/themes/theme_token_handler.cpp`), which is the authority; this
page names the ratios but does not repeat their values, which are listed
under "Contrast".

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
- Ignored and hidden packet text are lifted
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

### Token naming in QSS

Tokens are available to `.qss` files as `wstheme(Name)` placeholders
(the internal token name, for example `wstheme(HeaderBackground)`).  The
ThemeManager resolves each to the light or dark value depending on the
current appearance.

## Creating a custom theme

The recommended way is the Theme Designer (**View → Internals → Theme
Designer**, or the button on the **Theme** page of
**Edit → Preferences → Appearance**), which edits a copy of an existing
theme and writes the file for you.

To do it by hand:

1. Copy `wireshark/theme.jsonc` (or `stratoshark/theme.jsonc`, if you
   want to keep its surface tinting) to `<stem>.jsonc` in the personal
   themes directory shown in **About → Folders**.  Personal themes are
   flat files; there is no per-theme subdirectory.

2. Change `"name"` and adjust the colors you want.  You only need to
   set what you want to change; omitted tokens are derived from `brand`,
   `accent` and `palette`.

3. Select the theme in **Edit → Preferences → Appearance → Theme**.

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
`separator` line below the last toolbar row.  On macOS and Windows 11 such
a theme also tints the title bar of the main window and of dialogs, with
light or dark title text by the brightness of that color.  Windows 10,
Linux and themes without `palette.window` keep the native title bar and
toolbar look.
