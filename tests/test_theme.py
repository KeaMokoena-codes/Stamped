"""Issue #31: the Stamped colours must stay readable, distinct and tied to meaning."""

from app.plain_language import VerdictSummary
from app.theme import PALETTE, SYMBOLS, css, verdict_card_html


def _luminance(hex_colour: str) -> float:
    h = hex_colour.lstrip("#")
    channels = [int(h[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def _contrast(a: str, b: str) -> float:
    hi, lo = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def test_text_colours_meet_wcag_aa():
    pairs = [
        (PALETTE["text"], PALETTE["parchment"]),
        (PALETTE["text"], PALETTE["parchment_dark"]),
        (PALETTE["ink"], PALETTE["parchment"]),
        (PALETTE["deep"], PALETTE["parchment"]),
        ("#FFFFFF", PALETTE["ink"]),  # button text on the ink-teal primary colour
    ]
    for level in ("pass", "fail", "error"):
        text, background, _border = PALETTE[level]
        pairs.append((text, background))
    for foreground, background in pairs:
        assert _contrast(foreground, background) >= 4.5, (foreground, background)


def test_dark_mode_colours_meet_wcag_aa():
    pairs = [
        (PALETTE["dark_text"], PALETTE["dark_background"]),  # body text on the page
        (PALETTE["dark_text"], PALETTE["dark_panel"]),       # text in the sidebar and panels
        ("#FFFFFF", PALETTE["dark_primary"]),                # Streamlit prints white on the primary colour
    ]
    for foreground, background in pairs:
        assert _contrast(foreground, background) >= 4.5, (foreground, background)
    # buttons and the title rule must also stand out from the dark page (non-text contrast is 3:1)
    assert _contrast(PALETTE["dark_primary"], PALETTE["dark_background"]) >= 3.0
    assert _contrast(PALETTE["accent"], PALETTE["dark_background"]) >= 3.0


def test_verdict_borders_are_visible_against_the_page():
    for level in ("pass", "fail", "error"):
        assert _contrast(PALETTE[level][2], PALETTE["parchment"]) >= 3.0, level


def test_the_requested_teal_palette_is_in_use():
    assert (PALETTE["deep"], PALETTE["ink"], PALETTE["accent"]) == ("#092327", "#0B5351", "#00A9A5")
    assert PALETTE["accent"] in css()  # the accent is the title rule, and is not used for text


def test_the_three_verdicts_use_three_different_colours():
    assert len({PALETTE[level][2] for level in ("pass", "fail", "error")}) == 3
    assert len(set(SYMBOLS.values())) == 3


def test_brand_colours_are_not_verdict_colours():
    verdict_colours = {c.lower() for level in ("pass", "fail", "error") for c in PALETTE[level]}
    for brand in ("deep", "ink", "accent", "parchment", "parchment_dark", "dark_primary"):
        assert PALETTE[brand].lower() not in verdict_colours


def test_card_shows_the_verifiers_word_and_a_symbol_not_just_a_colour():
    for level, label in (("pass", "PASS"), ("fail", "FAIL"), ("error", "ERROR")):
        html = verdict_card_html(VerdictSummary(level, label, "h", "m", "n", ("f",)))
        assert f"RESULT: {label}" in html
        assert SYMBOLS[level] in html
        assert f"stamped-verdict--{level}" in html
    assert 'role="alert"' in verdict_card_html(VerdictSummary("fail", "FAIL", "h", "m", "n"))
    assert 'role="alert"' in verdict_card_html(VerdictSummary("error", "ERROR", "h", "m", "n"))
    assert 'role="status"' in verdict_card_html(VerdictSummary("pass", "PASS", "h", "m", "n"))


def test_card_html_is_escaped_and_markdown_safe():
    nasty = VerdictSummary("fail", "FAIL", "<script>alert(1)</script>", "<b>x</b>", "a & b", ("<img src=x>",))
    html = verdict_card_html(nasty)
    assert "<script>" not in html and "<img" not in html and "<b>x</b>" not in html
    assert "&lt;script&gt;" in html
    assert "\n" not in html and "    " not in html  # a blank line or indent would break Markdown


def test_unknown_level_is_shown_as_an_error_never_as_a_pass():
    html = verdict_card_html(VerdictSummary("surprise", "UNKNOWN", "h", "m", "n"))
    assert "stamped-verdict--error" in html and "stamped-verdict--pass" not in html


def test_css_is_single_line_and_does_not_recolour_normal_text():
    sheet = css()
    assert "\n" not in sheet
    assert "h1{border-bottom" in sheet and "color:" not in sheet.split(".stamped-verdict{")[0]


def _config():
    try:
        import tomllib
    except ImportError:  # Python 3.10
        return None
    from pathlib import Path

    return tomllib.loads((Path(__file__).resolve().parent.parent / ".streamlit" / "config.toml").read_text("utf-8"))


def test_streamlit_light_theme_matches_the_palette():
    config = _config()
    if config is None:
        return
    theme = config["theme"]["light"]
    assert theme["primaryColor"].lower() == PALETTE["ink"].lower()
    assert theme["backgroundColor"].lower() == PALETTE["parchment"].lower()
    assert theme["secondaryBackgroundColor"].lower() == PALETTE["parchment_dark"].lower()
    assert theme["textColor"].lower() == PALETTE["text"].lower()


def test_streamlit_dark_theme_matches_the_palette():
    config = _config()
    if config is None:
        return
    theme = config["theme"]["dark"]
    assert theme["primaryColor"].lower() == PALETTE["dark_primary"].lower()
    assert theme["backgroundColor"].lower() == PALETTE["dark_background"].lower()
    assert theme["secondaryBackgroundColor"].lower() == PALETTE["dark_panel"].lower()
    assert theme["textColor"].lower() == PALETTE["dark_text"].lower()


def test_the_menu_is_cut_down_to_the_light_dark_switch():
    config = _config()
    if config is None:
        return
    # "minimal" removes "Record screen", Print and the developer options; the light/dark switch stays
    # because both theme variants are defined above.
    assert config["client"]["toolbarMode"] == "minimal"
    assert "light" in config["theme"] and "dark" in config["theme"]