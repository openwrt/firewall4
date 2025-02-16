{%+ if (rule.family): -%}
	meta nfproto {{ fw4.nfproto(rule.family) }} {%+ endif -%}
{%+ include("zone-match.uc", { egress, rule }) -%}
{%+ if (verdict != "accept" && (zone.log & 1) && zone.log_limit): -%}
	limit name "{{ zone.name }}.log_limit" log prefix "{{ verdict }} {{ zone.name }} {{ egress ? "out" : "in" }}: "
		{%+ include("zone-verdict.uc", { fw4, zone: { ...zone, log: 0 }, rule, egress, verdict }) %}
{%+ else -%}
{%+  if (zone.counter): -%}
	counter {%+ endif -%}
{%+  if (verdict != "accept" && (zone.log & 1)): -%}
	log prefix "{{ verdict }} {{ zone.name }} {{ egress ? "out" : "in" }}: " {%+ endif -%}
{%   if (verdict == "reject"): -%}
	goto handle_reject comment "!fw4: reject {{ zone.name }} {{ fw4.nfproto(rule.family, true) }} traffic"
{%   else -%}
	{{ verdict }} comment "!fw4: {{ verdict }} {{ zone.name }} {{ fw4.nfproto(rule.family, true) }} traffic"
{%   endif -%}
{%  endif -%}
