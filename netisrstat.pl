#!/usr/bin/perl 

use strict;
use warnings;

use Getopt::Std;
use vars qw(%opts);

sub collect_top {
    my $interval = shift;
    open TOP, "top -SHb -d 2 -s $interval 1000 |" or die "Can't spawn top: $!";
    my $got_stats = 0;
    my $timestamp = time;
    my %top;
    while (<TOP>) {
        chomp;
        if (/^\s*PID\s/) {
            $got_stats++;
        } elsif($got_stats == 2) {
            s/^\s*//;
            my @d = split /\s+/, $_, 11;
            if ($d[10] and $d[10] =~ /^intr{swi\d+: netisr (\d+)}$/) {
                my $wsid = $1;
                my $pct = $d[9];
                $pct =~ s/%$//;
                $top{$wsid} = $pct;
            }
        }
    }
    return \%top;
}


sub collect_netisr {
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

getopts 'p', \%opts or die "$!";

if (@ARGV > 0) {
    $interval = $ARGV[0];
    if (@ARGV > 1) {
        $count = $ARGV[1];
    }
}

my ($pnetisr, $top, $netisr);
$pnetisr = &collect_netisr(\@proto_filter);
$top = &collect_top($interval);
my $ii = 1;
while (1) {
    $netisr = &collect_netisr(\@proto_filter);
    if ($opts{p}) {
        printf "\n%8s %2s %5s %6s %8s %8s %8s %5s %8s %4s\n",
            "Proto", "ID", "QLen", "WMark", "Handled", "Disp'd", "HDisp'd", "QDrop", "Queued", "%CPU";
        for my $proto (sort keys %{$netisr}) {
            for my $wsid (sort keys %{$netisr->{$proto}}) {
                my $row = $netisr->{$proto}{$wsid};
                my $prow = $pnetisr->{$proto}{$wsid};
                printf "%8s %2d %5d %6d %8d %8d %8d %5d %8d %4d\n",
                    $proto, $wsid, $row->{qlen}, $row->{wmark},
                    $row->{handled} - $prow->{handled},
                    $row->{dispd} - $prow->{dispd},
                    $row->{hdispd} - $prow->{hdispd},
                    $row->{qdrops} - $prow->{qdrops},
                    $row->{queued} - $prow->{queued},
                    $top->{$wsid} || 0;
            }
        }
    } else {
        my $ni = {};
        for my $proto (sort keys %{$netisr}) {
            for my $wsid (sort keys %{$netisr->{$proto}}) {
                $ni->{$wsid} = {}
                    unless defined $ni->{$wsid};
                my $nrow = $ni->{$wsid};
                my $row = $netisr->{$proto}{$wsid};
                my $prow = $pnetisr->{$proto}{$wsid};
                $nrow->{qlen} += $row->{qlen};
                $nrow->{wmark} += $row->{wmark};
                $nrow->{handled} += $row->{handled} - $prow->{handled};
                $nrow->{dispd} += $row->{dispd} - $prow->{dispd};
                $nrow->{hdispd} += $row->{hdispd} - $prow->{hdispd};
                $nrow->{qdrops} += $row->{qdrops} - $prow->{qdrops};
                $nrow->{queued} += $row->{queued} - $prow->{queued};
            }
        }
        printf "\n%2s %5s %6s %8s %8s %8s %5s %8s %4s\n",
            "ID", "QLen", "WMark", "Handled", "Disp'd", "HDisp'd", "QDrop", "Queued", "%CPU";
        for my $wsid (sort keys %{$ni}) {
            my $nrow = $ni->{$wsid};
            printf "%2d %5d %6d %8d %8d %8d %5d %8d %4d\n",
                $wsid, $nrow->{qlen}, $nrow->{wmark},
                $nrow->{handled}, $nrow->{dispd},
                $nrow->{hdispd}, $nrow->{qdrops},
                $nrow->{queued},
                $top->{$wsid} || 0;
        }
    }

    last
        if $count and $ii == $count;

    $pnetisr = $netisr;
    $top = &collect_top($interval);
    $ii++;
}
