#!/usr/bin/env perl
#
# $Id: build-man-pdfs.pl,v 1.8 2016/12/04 02:34:36 mjl Exp $

use strict;
use warnings;

sub cmd($)
{
    my ($cmd) = @_;
    print "$cmd\n";
    system("$cmd");
}

my @mans = ("scamper/scamper.1",
	    "utils/sc_ally/sc_ally.1",
	    "utils/sc_analysis_dump/sc_analysis_dump.1",
	    "utils/sc_attach/sc_attach.1",
	    "utils/sc_bdrmap/sc_bdrmap.1",
	    "utils/sc_filterpolicy/sc_filterpolicy.1",
	    "utils/sc_prefixscan/sc_prefixscan.1",
	    "utils/sc_remoted/sc_remoted.1",
	    "utils/sc_radargun/sc_radargun.1",
	    "utils/sc_speedtrap/sc_speedtrap.1",
	    "utils/sc_tbitblind/sc_tbitblind.1",
	    "utils/sc_tracediff/sc_tracediff.1",
	    "utils/sc_warts2json/sc_warts2json.1",
	    "utils/sc_warts2pcap/sc_warts2pcap.1",
	    "utils/sc_warts2text/sc_warts2text.1",
	    "utils/sc_wartscat/sc_wartscat.1",
	    "utils/sc_wartsdump/sc_wartsdump.1",
	    "scamper/libscamperfile.3",
	    "scamper/warts.5",
    );

cmd("mkdir man");
foreach my $man (@mans)
{
    cmd("groff -T ps -man $man | ps2pdf - >man/$1.pdf")
	if($man =~ /^.+\/(.+)$/)
}
