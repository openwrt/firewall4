{%+ if (zone.masq ^ zone.masq6): -%}
	meta nfproto {{ fw4.nfproto(zone.masq ? 4 : 6) }} {%+ endif -%}
{%+ include("zone-match.uc", { egress: true, rule }) -%}
	jump drop_invalid
