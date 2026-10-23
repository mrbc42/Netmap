"""Inline SVG icons for each device type - no external assets required."""

from __future__ import annotations

import base64

from .classify import DEVICE_TYPES

S = 'fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"'
W = 'fill="#fff"'

GLYPHS = {
    "router": f'<rect x="14" y="32" width="36" height="14" rx="3" {S}/><path d="M22 32 18 19M42 32l4-13" {S}/>'
              f'<circle cx="21" cy="39" r="2" {W}/><circle cx="28" cy="39" r="2" {W}/><path d="M36 39h8" {S}/>',
    "firewall": f'<rect x="14" y="17" width="36" height="30" rx="2" {S}/><path d="M14 27h36M14 37h36M26 17v10M38 27v10M26 37v10" {S}/>',
    "switch": f'<rect x="11" y="24" width="42" height="16" rx="3" {S}/>'
              + "".join(f'<rect x="{16 + i * 7}" y="29" width="4" height="6" {W}/>' for i in range(5)),
    "access_point": f'<path d="M18 30a20 20 0 0 1 28 0M23 36a12 12 0 0 1 18 0" {S}/><circle cx="32" cy="42" r="3" {W}/>'
                    f'<path d="M20 50h24" {S}/>',
    "server": "".join(f'<rect x="17" y="{15 + i * 12}" width="30" height="9" rx="2" {S}/><circle cx="23" cy="{19.5 + i * 12}" r="1.6" {W}/>'
                      f'<path d="M34 {19.5 + i * 12}h8" stroke="#fff" stroke-width="2" stroke-linecap="round"/>' for i in range(3)),
    "nas": f'<rect x="19" y="14" width="26" height="36" rx="3" {S}/><path d="M19 32h26" {S}/>'
           f'<circle cx="38" cy="23" r="2" {W}/><circle cx="38" cy="41" r="2" {W}/><path d="M24 23h7M24 41h7" stroke="#fff" stroke-width="2" stroke-linecap="round"/>',
    "hypervisor": f'<path d="M32 15 50 24 32 33 14 24Z" {S}/><path d="M14 32l18 9 18-9M14 40l18 9 18-9" {S}/>',
    "workstation": f'<rect x="13" y="16" width="38" height="25" rx="3" {S}/><path d="M32 41v7M23 48h18" {S}/>',
    "phone": f'<rect x="22" y="12" width="20" height="40" rx="4" {S}/><circle cx="32" cy="46" r="1.8" {W}/><path d="M29 17h6" {S}/>',
    "printer": f'<path d="M22 24V14h20v10" {S}/><rect x="13" y="24" width="38" height="16" rx="3" {S}/>'
               f'<path d="M22 36h20v13H22z" {S}/><circle cx="45" cy="30" r="1.6" {W}/>',
    "camera": f'<rect x="12" y="22" width="30" height="20" rx="4" {S}/><path d="m42 28 10-5v18l-10-5" {S}/>'
              f'<circle cx="27" cy="32" r="5" {S}/>',
    "media": f'<rect x="12" y="16" width="40" height="26" rx="3" {S}/><path d="M24 48h16" {S}/><path d="M29 23v12l10-6z" {W}/>',
    "iot": f'<rect x="21" y="21" width="22" height="22" rx="3" {S}/><rect x="27" y="27" width="10" height="10" {W}/>'
           f'<path d="M27 14v7M37 14v7M27 43v7M37 43v7M14 27h7M14 37h7M43 27h7M43 37h7" {S}/>',
    "unknown": f'<path d="M25 25a7 7 0 1 1 10 6c-2 1-3 3-3 5v2" {S}/><circle cx="32" cy="45" r="2.2" {W}/>',
    "internet": f'<path d="M22 44h22a8 8 0 0 0 1-16 11 11 0 0 0-21-3 9 9 0 0 0-2 19z" {S}/>',
    "segment": f'<rect x="10" y="24" width="44" height="16" rx="3" {S}/>'
               + "".join(f'<rect x="{14 + i * 6}" y="29" width="3" height="6" {W}/>' for i in range(7)),
    "hop": f'<circle cx="32" cy="32" r="13" {S}/><path d="M32 19v26M19 32h26M23 23l18 18M41 23 23 41" stroke="#fff" stroke-width="2" stroke-linecap="round" opacity=".7"/>',
}

EXTRA_COLOURS = {"internet": "#0284c7", "segment": "#475569", "hop": "#78716c"}


def colour(kind: str) -> str:
    return DEVICE_TYPES.get(kind, ("", EXTRA_COLOURS.get(kind, "#64748b")))[1]


def svg(kind: str, ring: str | None = None) -> str:
    c = colour(kind)
    ring_el = f'<circle cx="32" cy="32" r="30" fill="none" stroke="{ring}" stroke-width="3"/>' if ring else ""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">'
            f'<circle cx="32" cy="32" r="28" fill="{c}"/>{ring_el}{GLYPHS.get(kind, GLYPHS["unknown"])}</svg>')


def data_uri(kind: str) -> str:
    return "data:image/svg+xml;base64," + base64.b64encode(svg(kind).encode()).decode()


def all_icons() -> dict[str, str]:
    return {k: data_uri(k) for k in GLYPHS}
