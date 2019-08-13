ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS=tls_traffic
tls_traffic_SOURCES=tls_traffic.c fields.c fields.h
tls_traffic_LDADD=-lunirec -ltrap -lpthread
EXTRA_DIST=README.md tls_traffic.sup
pkgdocdir=${docdir}/tls_traffic
pkgdoc_DATA=README.md
SUBDIRS=munin
muninsupdir=${nemeasupdir}/munin
muninsup_DATA=tls_traffic.sup
include ../aminclude.am
