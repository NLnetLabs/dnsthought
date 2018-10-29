bin_PROGRAMS = atlas2dnst iter_dnsts cap_counter mk_asn_tables lookup_asn lookup_probe sort_dnst
AM_CFLAGS = -Ijsmn

atlas2dnst_SOURCES = atlas2dnst.c jsmn/jsmn.c
sort_dnst_SOURCES = sort_dnst.c
iter_dnsts_SOURCES = iter_dnsts.c rbtree.c rr-iter.c
cap_counter_SOURCES= cap_counter.c table4.c table6.c ranges.c rbtree.c probes.c
mk_asn_tables_SOURCES = mk_asn_tables.c
lookup_asn_SOURCES = lookup_asn.c table4.c table6.c ranges.c
lookup_probe_SOURCES = lookup_probe.c probes.c
iter_dnsts_LDADD = @LIBOBJS@

