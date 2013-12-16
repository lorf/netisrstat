#!/usr/bin/perl 

use strict;
use warnings;

sub collect {
    my $proto_filter = shift;
    open STAT, "netstat -Q |" or die "Can't spawn \"netstat -Q\": $!";
    my $got_stats;
    my $timestamp = time;
    my %data;
    while (<STAT>) {
        chomp;
        s/^\s*//;
        if (/^WSID/) {
            $got_stats = 1;
        } elsif ($got_stats) {
            my @row = split /\s+/, $_;
            next
                unless grep { $row[2] =~ /^$_$/i } @{$proto_filter};
            $data{$row[2]}{$row[0]} = {
                wsid    => $row[0],
                proto   => $row[2],
                qlen    => $row[3],
                wmark   => $row[4],
                dispd   => $row[5],
                hdispd  => $row[6],
                qdrops  => $row[7],
                queued  => $row[8],
                handled => $row[9],
                time    => $timestamp,
            };
        }
    }
    close STAT;
    return \%data;
}

my $interval = 1;
my $count = 0;
my @proto_filter = qw(ip arp ether);

if (@ARGV > 0) {
    $interval = $ARGV[0];
    if (@ARGV > 1) {
        $count = $ARGV[1];
    }
}

my ($pdata, $data);
$pdata = &collect(\@proto_filter);
sleep $interval;
my $ii = 1;
while (1) {
    $data = &collect(\@proto_filter);
    printf "%8s %2s %5s %6s %8s %8s %8s %5s %8s\n",
        "Name", "ID", "QLen", "WMark", "Handled", "Disp'd", "HDisp'd", "QDrops", "Queued";
    for my $proto (sort keys %{$data}) {
        for my $wsid (sort keys %{$data->{$proto}}) {
            my $row = $data->{$proto}{$wsid};
            my $prow = $pdata->{$proto}{$wsid};
            printf "%8s %2d %5d %6d %8d %8d %8d %5d %8d\n",
                $proto, $wsid, $row->{qlen}, $row->{wmark},
                $row->{handled} - $prow->{handled},
                $row->{dispd} - $prow->{dispd},
                $row->{hdispd} - $prow->{hdispd},
                $row->{qdrops} - $prow->{qdrops},
                $row->{queued} - $prow->{queued};
        }
    }

    last
        if $count and $ii == $count;

    $pdata = $data;
    sleep $interval;
    $ii++;
}
