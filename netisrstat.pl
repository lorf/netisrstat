#!/usr/bin/perl 

use strict;
use warnings;

use Getopt::Std;
use vars qw(%opts $interval $count $flag_collect_stats);

sub usage {
    print <<_EOT_;
usage: $0 [-p] [-f <proto_filter>] [<interval> [<count>]]
options:
  -p         Display statistics by protocol and ISR
             (default is to display by ISR);
  -f filter  Protocol display filter (e.g. "ether,ip", empty by default);
  -S         Show values per interval rather than per second.
_EOT_
    exit 1;
}

sub collect_proc {
    my $cmd = "ps Haxww -o %cpu,comm";
    open PROC, "$cmd |" or die "Can't spawn \"$cmd\": $!";
    my %top;
    my $ln = 0;
    while (<PROC>) {
        chomp;
        s/^\s*//;
        if ($ln > 0) {  # Skip header
            my ($cpu, $cmd) = split /\s+/, $_, 2;
            if ($cmd and $cmd =~ /\bnetisr\s*(\d+)$/) {
                $top{$1} = $cpu;
            }
        }
        $ln++;
    }
    close PROC;
    return \%top;
}


sub collect_netisr {
    my $proto_filter = shift;
    open STAT, "netstat -Q |" or die "Can't spawn \"netstat -Q\": $!";
    my $got_stats;
    my %data;
    while (<STAT>) {
        chomp;
        s/^\s*//;
        if (/^WSID/) {
            $got_stats = 1;
        } elsif ($got_stats) {
            my @row = split /\s+/, $_;
            next
                if @{$proto_filter} and not grep { $row[2] eq $_ } @{$proto_filter};
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
            };
        }
    }
    close STAT;
    return \%data;
}

sub timer_handler {
    alarm $interval;
    $flag_collect_stats = 1;
}

sub print_stats {
    my $time = shift;
    my $netisr = shift;
    my $pnetisr = shift;
    my $top = shift;

    if ($opts{p}) {
        printf "\n%8s %2s %4s %5s %6s %8s %8s %8s %5s %8s\n",
            "Proto", "ID", "%CPU", "QLen", "WMark", "Handled", "Disp'd", "HDisp'd", "QDrop", "Queued";
        for my $proto (sort keys %{$netisr}) {
            for my $wsid (sort keys %{$netisr->{$proto}}) {
                my $row = $netisr->{$proto}{$wsid};
                my $prow = $pnetisr->{$proto}{$wsid};
                my $fmt = "%8s %2d %4.1f %5d %6d %8d %8d %8d %5d %8d\n";
                if ($opts{S}) {
                    printf $fmt,
                        $proto, $wsid, $top->{$wsid} || 0,
                        $row->{qlen}, $row->{wmark},
                        $row->{handled} - $prow->{handled},
                        $row->{dispd} - $prow->{dispd},
                        $row->{hdispd} - $prow->{hdispd},
                        $row->{qdrops} - $prow->{qdrops},
                        $row->{queued} - $prow->{queued};
                } else {
                    printf $fmt,
                        $proto, $wsid, $top->{$wsid} || 0,
                        $row->{qlen}, $row->{wmark},
                        ($row->{handled} - $prow->{handled}) / $time,
                        ($row->{dispd} - $prow->{dispd}) / $time,
                        ($row->{hdispd} - $prow->{hdispd}) / $time,
                        ($row->{qdrops} - $prow->{qdrops}) / $time,
                        ($row->{queued} - $prow->{queued}) / $time;
                }
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
        printf "\n%2s %4s %5s %6s %8s %8s %8s %5s %8s\n",
            "ID", "%CPU", "QLen", "WMark", "Handled", "Disp'd", "HDisp'd", "QDrop", "Queued";
        for my $wsid (sort keys %{$ni}) {
            my $nrow = $ni->{$wsid};
            my $fmt = "%2d %4.1f %5d %6d %8d %8d %8d %5d %8d\n";
            if ($opts{S}) {
                printf $fmt,
                    $wsid, $top->{$wsid} || 0,
                    $nrow->{qlen}, $nrow->{wmark},
                    $nrow->{handled}, $nrow->{dispd},
                    $nrow->{hdispd}, $nrow->{qdrops},
                    $nrow->{queued};
            } else {
                printf $fmt,
                    $wsid, $top->{$wsid} || 0,
                    $nrow->{qlen}, $nrow->{wmark},
                    $nrow->{handled} / $time, $nrow->{dispd} / $time,
                    $nrow->{hdispd} / $time, $nrow->{qdrops} / $time,
                    $nrow->{queued} / $time;
            }
        }
    }
}

$interval = 1;
$count = 0;
my @proto_filter = ();

&usage
    if not getopts 'hpf:S', \%opts or $opts{h};

if (defined $opts{f}) {
    @proto_filter = split ',', $opts{f};
}

$interval = shift @ARGV
    if @ARGV;
$count = shift @ARGV
    if @ARGV;

{
    my $ii = 1;
    my $continue = 1;
    my ($prev_netisr, $prev_timestamp);
    local $SIG{'TERM'} = sub { $continue = 0 };
    local $SIG{'ALRM'} = \&timer_handler;

    &timer_handler;

    while ($continue) {
        if ($flag_collect_stats) {
            my $timestamp = time;
            my $netisr = &collect_netisr(\@proto_filter);
            my $top = &collect_proc();

            if ($prev_netisr) {
                &print_stats($timestamp - $prev_timestamp, $netisr, $prev_netisr, $top);
            }
            $prev_netisr = $netisr;
            $prev_timestamp = $timestamp;

            last
                if $count and $ii == $count;
            $ii++;
            $flag_collect_stats = 0;
        }

        # Sleep. select is used as interruptable sleep as the use of sleep is not
        # recommended in perlfunc section on alarm
        select undef, undef, undef, $interval;
    }
}
