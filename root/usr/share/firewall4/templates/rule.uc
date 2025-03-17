{%+ if (rule.family && !rule.has_addrs): -%}
	meta nfproto {{ fw4.nfproto(rule.family) }} {%+ endif -%}
{%+ if (!rule.proto.any && !rule.has_ports && !rule.icmp_types && !rule.icmp_codes && !rule.set_helper): -%}
	meta l4proto {{ fw4.l4proto(rule.family, rule.proto) }} {%+ endif -%}
{%+ if (rule.iifnames): -%}
	iifname {{ fw4.set(rule.iifnames) }} {%+ endif -%}
{%+ if (rule.oifnames): -%}
	oifname {{ fw4.set(rule.oifnames) }} {%+ endif -%}
{%+ if (rule.saddrs_pos): -%}
	{{ fw4.ipproto(rule.family) }} saddr {{ fw4.set(rule.saddrs_pos) }} {%+ endif -%}
{%+ if (rule.saddrs_neg): -%}
	{{ fw4.ipproto(rule.family) }} saddr != {{ fw4.set(rule.saddrs_neg) }} {%+ endif -%}
{%+ for (let a in rule.saddrs_masked): -%}
	{{ fw4.ipproto(rule.family) }} saddr & {{ a.mask }} {{ a.invert ? '!=' : '==' }} {{ a.addr }} {%+ endfor -%}
{%+ if (rule.daddrs_pos): -%}
	{{ fw4.ipproto(rule.family) }} daddr {{ fw4.set(rule.daddrs_pos) }} {%+ endif -%}
{%+ if (rule.daddrs_neg): -%}
	{{ fw4.ipproto(rule.family) }} daddr != {{ fw4.set(rule.daddrs_neg) }} {%+ endif -%}
{%+ for (let a in rule.daddrs_masked): -%}
	{{ fw4.ipproto(rule.family) }} daddr & {{ a.mask }} {{ a.invert ? '!=' : '==' }} {{ a.addr }} {%+ endfor -%}
{%+ if (rule.sports_pos): -%}
	{{ rule.proto.name }} sport {{ fw4.set(rule.sports_pos) }} {%+ endif -%}
{%+ if (rule.sports_neg): -%}
	{{ rule.proto.name }} sport != {{ fw4.set(rule.sports_neg) }} {%+ endif -%}
{%+ if (rule.dports_pos): -%}
	{{ rule.proto.name }} dport {{ fw4.set(rule.dports_pos) }} {%+ endif -%}
{%+ if (rule.dports_neg): -%}
	{{ rule.proto.name }} dport != {{ fw4.set(rule.dports_neg) }} {%+ endif -%}
{%+ if (rule.smacs_pos): -%}
	ether saddr {{ fw4.set(rule.smacs_pos) }} {%+ endif -%}
{%+ if (rule.smacs_neg): -%}
	ether saddr != {{ fw4.set(rule.smacs_neg) }} {%+ endif -%}
{%+ if (rule.icmp_types): -%}
	{{ (rule.family == 4) ? "icmp" : "icmpv6" }} type {{ fw4.set(rule.icmp_types) }} {%+ endif -%}
{%+ if (rule.icmp_codes): -%}
	{{ (rule.family == 4) ? "icmp" : "icmpv6" }} type . {{ (rule.family == 4) ? "icmp" : "icmpv6" }} code {{
		fw4.set(rule.icmp_codes, true)
	}} {%+ endif -%}
{%+ if (rule.helper): -%}
	ct helper{% if (rule.helper.invert): %} !={% endif %} {{ fw4.quote(rule.helper.name, true) }} {%+ endif -%}
{%+ if (rule.limit): -%}
	limit rate {{ rule.limit.rate }}/{{ rule.limit.unit }}
	{%- if (rule.limit_burst): %} burst {{ rule.limit_burst }} packets{% endif %} {%+ endif -%}
{%+ if (rule.start_date && rule.stop_date): -%}
	meta time {{ fw4.datestamp(rule.start_date) }}-{{ fw4.datestamp(rule.stop_date) }} {%+
   elif (rule.start_date): -%}
	meta time >= {{ fw4.datestamp(rule.start_date) }} {%+
   elif (rule.stop_date): -%}
	meta time <= {{ fw4.datestamp(rule.stop_date) }} {%+
   endif -%}
{%+ if (rule.start_time && rule.stop_time): -%}
	meta hour {{ fw4.time(rule.start_time) }}-{{ fw4.time(rule.stop_time) }} {%+
   elif (rule.start_time): -%}
	meta hour >= {{ fw4.time(rule.start_time) }} {%+
   elif (rule.stop_time): -%}
	meta hour <= {{ fw4.time(rule.stop_time) }} {%+
   endif -%}
{%+ if (rule.weekdays): -%}
	meta day{% if (rule.weekdays.invert): %} !={% endif %} {{ fw4.set(rule.weekdays.days) }} {%+ endif -%}
{%+ if (rule.mark && rule.mark.mask < 0xFFFFFFFF): -%}
	meta mark and {{ fw4.hex(rule.mark.mask) }} {{
		rule.mark.invert ? '!=' : '=='
	}} {{ fw4.hex(rule.mark.mark) }} {%+ endif -%}
{%+ if (rule.mark && rule.mark.mask == 0xFFFFFFFF): -%}
	meta mark{% if (rule.mark.invert): %} !={% endif %} {{ fw4.hex(rule.mark.mark) }} {%+ endif -%}
{%+ if (rule.dscp): -%}
	{{ fw4.ipproto(rule.family) }} dscp{% if (rule.dscp.invert): %} !={% endif %} {{ fw4.hex(rule.dscp.dscp) }} {%+ endif -%}
{%+ if (rule.ipset): -%}
	{{ fw4.concat(rule.ipset.fields) }}{{
		rule.ipset.invert ? ' !=' : ''
	}} @{{ rule.ipset.name }} {%+ endif -%}
{%+ if (rule.log && rule.log_limit): -%}
	limit rate {{ rule.log_limit.rate }}/{{ rule.log_limit.unit }} log prefix {{ fw4.quote(rule.log, true) }}
		{%+ include("rule.uc", { fw4, zone, rule: { ...rule, log: 0 } }) %}
{%+ elif (rule.log && zone?.log_limit): -%}
	limit name "{{ zone.name }}.log_limit" log prefix {{ fw4.quote(rule.log, true) }}
		{%+ include("rule.uc", { fw4, zone, rule: { ...rule, log: 0 } }) %}
{%+ else -%}
{%+  if (rule.counter): -%}
	counter {%+ endif -%}
{%+  if (rule.log): -%}
	log prefix {{ fw4.quote(rule.log, true) }} {%+ endif -%}
{%+  if (rule.target == "mark"): -%}
	meta mark set {{
		(rule.set_xmark.mask == 0xFFFFFFFF)
			? fw4.hex(rule.set_xmark.mark)
			: (rule.set_xmark.mark == 0)
				? `mark and ${fw4.hex(~rule.set_xmark.mask & 0xFFFFFFFF)}`
				: (rule.set_xmark.mark == rule.set_xmark.mask)
					? `mark or ${fw4.hex(rule.set_xmark.mark)}`
					: (rule.set_xmark.mask == 0)
						? `mark xor ${fw4.hex(rule.set_xmark.mark)}`
						: `mark and ${fw4.hex(~rule.set_xmark.mask & 0xFFFFFFFF)} xor ${fw4.hex(rule.set_xmark.mark)}`
	}} {%+
     elif (rule.target == "dscp"): -%}
	{{ fw4.ipproto(rule.family) }} dscp set {{ fw4.hex(rule.set_dscp.dscp) }} {%+
     elif (rule.target == "notrack"): -%}
	notrack {%+
     elif (rule.target == "helper"): -%}
	ct helper set {{ fw4.quote(rule.set_helper.name, true) }} {%+
     elif (rule.jump_chain): -%}
	jump {{ rule.jump_chain }} {%+
     elif (rule.target): -%}
	{{ rule.target }} {%+
     endif -%}
comment {{ fw4.quote(`!fw4: ${rule.name}`, true) }}
{%+ endif -%}
