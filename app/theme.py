"""Stamped colours and the verdict card (Issue #31).

The palette is taken from what the product is, a digital notary for evidence:
  INK        navy   notary / court ink      -> headings, buttons (see .streamlit/config.toml)
  PARCHMENT  cream  the paper evidence is on -> page background (see .streamlit/config.toml)
  BRASS      brass  the seal / stamp         -> accent rule under the title, card trim

Red, green and amber are reserved for FAIL, PASS and ERROR and for nothing else, so a brand
colour can never be read as a verdict. Colour is never the only signal: every verdict also
carries a symbol and the word the verifier used (PASS / FAIL / ERROR).

Every text/background pair below was checked against WCAG AA (4.5:1 for text).
"""

from __future__ import annotations

from html import escape

from app.plain_language import VerdictSummary

PALETTE = {
    "ink": "#1B2A41",
    "parchment": "#F7F3E8",
    "parchment_dark": "#EBE4D2",
    "text": "#1F2933",
    "brass": "#8A6420",
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
    brass = PALETTE["brass"]
    return (
        "<style>"
        f"h1{{border-bottom:3px solid {brass};padding-bottom:.25rem;}}"
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


def inject_theme() -> None:
    import streamlit as st

    st.markdown(css(), unsafe_allow_html=True)


def show_verdict(summary: VerdictSummary) -> None:
    import streamlit as st

    st.markdown(verdict_card_html(summary), unsafe_allow_html=True)