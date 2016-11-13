#!/usr/bin/env perl
#
# $Id: bootstrap.pl,v 1.11 2016/10/19 02:14:52 mjl Exp $
#
# script to ship scamper with generated configure script ready to build.

use strict;
use warnings;

my @aclocal = ("aclocal", "aclocal-1.11", "aclocal-1.9");
my @libtoolize = ("libtoolize", "glibtoolize");
my @autoheader = ("autoheader", "autoheader-2.68", "autoheader259");
my @automake = ("automake", "automake-1.11");
my @autoconf = ("autoconf", "autoconf-2.68");

# where to get the AX_* m4 files
my $ax_url = "http://git.savannah.gnu.org/gitweb/" .
    "?p=autoconf-archive.git;a=blob_plain;f=m4";

# the AX m4 files to get, and their SHA-2 256 checksums
my %ax;
$ax{"ax_check_openssl.m4"} =
    "8574f228ef7294a8d53863f45f7f1456e087bbfadda14429f452a027d87f81a3";
$ax{"ax_gcc_builtin.m4"} =
    "0f70a54de0c4c8579eee252f4d8549d2b49d8be000e16e37a5de63f774bd4f4c";

sub which($)
{
    my ($bin) = @_;
    my $rc = undef;
    open(WHICH, "which $bin 2>/dev/null |") or die "could not which";
    while(<WHICH>)
    {
	chomp;
	$rc = $_;
	last;
    }
    close WHICH;
    return $rc;
}

sub tryexec
{
    my $args = shift;
    my $rc = -1;

    foreach my $util (@_)
    {
	$util = which($util);
	if(defined($util))
	{
	    print "===> $util $args\n";
	    $rc = system("$util $args");
	    last;
	}
    }

    return $rc;
}

if(!-d "m4")
{
    exit -1 if(!(mkdir "m4"));
}

foreach my $ax (sort keys %ax)
{
    if(!-r "m4/$ax")
    {
	my $cmd;
	foreach my $util ("fetch", "wget", "ftp")
	{
	    my $fetch = which($util);
	    next if(!defined($fetch));

	    if($util eq "wget")
	    {
		$cmd = "wget -O m4/$ax \"$ax_url/$ax\"";
		last;
	    }
	    elsif($util eq "fetch")
	    {
		$cmd = "fetch -o m4/$ax \"$ax_url/$ax\"";
		last;
	    }
	    elsif($util eq "ftp")
	    {
		$cmd = "ftp -o m4/$ax \"$ax_url/$ax\"";
		last;
	    }
	}
	if(!defined($cmd))
	{
	    print "could not download $ax: no download utility\n";
	    exit -1;
	}

	print "===> $cmd\n";
	system("$cmd");
    }

    my $sum;
    foreach my $util ("sha256", "sha256sum", "shasum")
    {
	my $sha256 = which($util);
	next if(!defined($sha256));
	$sha256 .= " -a 256" if($util eq "shasum");

	open(SUM, "$sha256 m4/$ax |") or die "could not $sha256 m4/$ax";
	while(<SUM>)
	{
	    chomp;
	    if(/^SHA256 \(m4\/.+?\) \= (.+)/) {
		$sum = $1;
		last;
	    } elsif(/^(.+?)\s+m4\//) {
		$sum = $1;
		last;
	    }
	}
	close SUM;
	last if(defined($sum));
    }
    if(!defined($sum) || $sum ne $ax{$ax})
    {
	print STDERR "$ax has unexpected sha256 sum\n";
	exit -1;
    }
    else
    {
	print STDERR "$ax has valid sha256 sum\n";
    }
}

if(tryexec("", @aclocal) != 0)
{
    print STDERR "could not exec aclocal\n";
    exit -1;
}

if(tryexec("--force --copy", @libtoolize) != 0)
{
    print STDERR "could not libtoolize\n";
    exit -1;
}

if(tryexec("", @autoheader) != 0)
{
    print STDERR "could not autoheader\n";
    exit -1;
}

if(tryexec("--add-missing --copy --foreign", @automake) != 0)
{
    print STDERR "could not automake\n";
    exit -1;
}

if(tryexec("", @autoconf) != 0)
{
    print STDERR "could not autoconf\n";
    exit -1;
}

exit 0;
