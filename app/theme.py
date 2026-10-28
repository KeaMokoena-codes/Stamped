"""Stamped colours and the verdict card (Issue #31).

The palette is a three-step teal family on parchment paper, with a matching dark mode:
  DEEP       #092327  darkest teal -> light mode: body text. Dark mode: the page background
  INK        #0B5351  mid teal     -> light mode: buttons and links. Dark mode: sidebar and panels
  ACCENT     #00A9A5  bright teal  -> the decorative rule under the title; never used for text
  PARCHMENT  cream                 -> light mode: the paper evidence is on. Dark mode: body text
  DARK_PRIMARY #05827F            -> dark-mode buttons: a shade between INK and ACCENT, light enough to
                                     stand out on the dark page yet dark enough for white button text
(the Streamlit settings are in .streamlit/config.toml)

The verdict card keeps its own light background and dark text in both modes, so a PASS / FAIL / ERROR
reads exactly the same whichever mode someone is using.

Red, green and amber are reserved for FAIL, PASS and ERROR and for nothing else, so a brand
colour can never be read as a verdict. Teal sits between blue and green, so colour is never the
only signal: every verdict also carries a symbol, the word the verifier used (PASS / FAIL / ERROR)
and a heavy left border.

Every text/background pair below was checked against WCAG AA (4.5:1 for text). The accent is a
decorative rule only (too light for text on parchment), so it is not held to a text ratio.
"""

from __future__ import annotations

from html import escape

from app.plain_language import VerdictSummary

PALETTE = {
    "deep": "#092327",
    "ink": "#0B5351",
    "accent": "#00A9A5",
    "parchment": "#F7F3E8",
    "parchment_dark": "#EBE4D2",
    "text": "#092327",
    # dark mode
    "dark_background": "#092327",
    "dark_panel": "#0B5351",
    "dark_text": "#F7F3E8",
    "dark_primary": "#05827F",
    # verdicts: (text, background, border)
    "pass": ("#14532D", "#E3F1E8", "#1E6B45"),
    "fail": ("#7A1B1B", "#FBE6E4", "#A4262C"),
    "error": ("#5C3B00", "#FFF1D6", "#B26A00"),
}

SYMBOLS = {"pass": "\u2714", "fail": "\u2716", "error": "\u26A0"}  # check, cross, warning


def _verdict_css() -> str:
    rules = []
    for level in ("pass", "fail", "error"):
        text, background, border = PALETTE[level]
        rules.append(
            f".stamped-verdict--{level}{{background:{background};border-color:{border};}}"
            f".stamped-verdict--{level},.stamped-verdict--{level} *{{color:{text};}}"
        )
    return "".join(rules)


def css() -> str:
    """The only custom CSS. Deliberately small: no colour overrides outside the verdict card,
    so Streamlit's own light/dark theme keeps working for everything else."""
    accent = PALETTE["accent"]
    return (
        "<style>"
        f"h1{{border-bottom:3px solid {accent};padding-bottom:.25rem;}}"
        ".stamped-verdict{border:2px solid;border-left-width:10px;border-radius:6px;"
        "padding:1rem 1.25rem;margin:1rem 0;}"
        ".stamped-verdict__label{font-weight:700;letter-spacing:.06em;font-size:1.05rem;}"
        ".stamped-verdict__headline{font-size:1.25rem;font-weight:600;margin:.4rem 0;}"
        ".stamped-verdict p{margin:.35rem 0;}"
        ".stamped-verdict ul{margin:.5rem 0 0 1.1rem;padding:0;}"
        f"{_verdict_css()}"
        "</style>"
    )


def verdict_card_html(summary: VerdictSummary) -> str:
    """A single-line HTML block (no blank lines or indentation, which Markdown would break).

    Everything dynamic is HTML-escaped: verifier text can never inject markup.
    """
    level = summary.level if summary.level in SYMBOLS else "error"
    role = "status" if level == "pass" else "alert"
    facts = "".join(f"<li>{escape(line)}</li>" for line in summary.facts)
    facts_html = f"<ul>{facts}</ul>" if facts else ""
    return (
        f'<div class="stamped-verdict stamped-verdict--{level}" role="{role}">'
        f'<div class="stamped-verdict__label">{SYMBOLS[level]} RESULT: {escape(summary.label)}</div>'
        f'<div class="stamped-verdict__headline">{escape(summary.headline)}</div>'
        f"<p>{escape(summary.what_it_means)}</p>"
        f"<p><strong>What to do next:</strong> {escape(summary.next_step)}</p>"
        f"{facts_html}"
        "</div>"
    )


def demo_banner_html() -> str:
    """The fixed demo warning uses the product palette and contains no user data."""
    background = PALETTE["deep"]
    foreground = PALETTE["parchment"]
    border = PALETTE["accent"]
    return (
        '<div class="stamped-demo-banner" role="note" '
        f'style="background:{background};color:{foreground};border-left:6px solid {border};'
        'padding:.75rem 1rem;margin:1rem 0;border-radius:4px;font-weight:600">'
        "Demo mode: sign-in by user ID, synthetic data only. Not for real evidence."
        "</div>"
    )


def inject_theme() -> None:
    import streamlit as st

    st.markdown(css(), unsafe_allow_html=True)


def show_verdict(summary: VerdictSummary) -> None:
    import streamlit as st

    st.markdown(verdict_card_html(summary), unsafe_allow_html=True)