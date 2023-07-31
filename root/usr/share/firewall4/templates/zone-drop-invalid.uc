{%+ if (zone.masq ^ zone.masq6): -%}
	meta nfproto {{ fw4.nfproto(zone.masq ? 4 : 6) }} {%+ endif -%}
{%+ include("zone-match.uc", { egress: true, rule }) -%}
ct state invalid {%+ if ((zone.log & 1) && zone.log_limit): -%}
	limit name "{{ zone.name }}.log_limit" log prefix "drop {{ zone.name }} invalid ct state: "
		{%+ include("zone-drop-invalid.uc", { fw4, zone: { ...zone, log: 0 }, rule }) %}
{%+ else -%}
{%+  if (zone.counter): -%}
	counter {%+ endif -%}
{%+  if (zone.log & 1): -%}
	log prefix "drop {{ zone.name }} invalid ct state: " {%+ endif -%}
drop comment "!fw4: Prevent NAT leakage"
{%+ endif -%}
