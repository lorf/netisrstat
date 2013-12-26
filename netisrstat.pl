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

sub collect_cpu_stats {
    my $cmd = "ps Haxww -o %cpu,comm";
    open PROC, "$cmd |" or die "Can't spawn \"$cmd\": $!";
    my %cpu;
    my $ln = 0;
    while (<PROC>) {
        chomp;
        s/^\s*//;
        if ($ln > 0) {  # Skip header
            my ($cpu, $cmd) = split /\s+/, $_, 2;
            if ($cmd and $cmd =~ /\bnetisr\s*(\d+)$/) {
                $cpu{$1} = $cpu;
            }
        }
        $ln++;
    }
    close PROC;
    return \%cpu;
}


sub collect_netisr_stats {
    my $proto_filter = shift;
    open STAT, "netstat -Q |" or die "Can't spawn \"netstat -Q\": $!";
    my $got_stats;
    my %stats;
    while (<STAT>) {
        chomp;
        s/^\s*//;
        if (/^WSID/) {
            $got_stats = 1;
        } elsif ($got_stats) {
            my @row = split /\s+/, $_;
            next
                if @{$proto_filter} and not grep { $row[2] eq $_ } @{$proto_filter};
            $stats{$row[2]}{$row[0]} = {
                id    => $row[0],
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
    return \%stats;
}

sub timer_handler {
    alarm $interval;
    $flag_collect_stats = 1;
}

sub print_stats {
    my $time = shift;
    my $netisr_stats = shift;
    my $prev_netisr_stats = shift;
    my $cpu_stats = shift;

    my %out = ();
    my %out_proto_totals = ();
    my %out_totals = ();
    my $outproto = "-";
    my $outdiv = $opts{S} ? 1 : $time;

    for my $proto (sort keys %{$netisr_stats}) {
        $outproto = $proto
            if $opts{p};

        for my $id (sort keys %{$netisr_stats->{$proto}}) {
            my $row = $netisr_stats->{$proto}{$id};
            my $prow = $prev_netisr_stats->{$proto}{$id};
            $out{$outproto}{$id} = {}
                unless defined $out{$outproto}{$id};
            my $outrow = $out{$outproto}{$id};

            $outrow->{cpu} = $cpu_stats->{$id} || 0;
            $outrow->{qlen} += $row->{qlen};
            $outrow->{wmark} += $row->{wmark};
            $outrow->{handled} += ($row->{handled} - $prow->{handled}) / $outdiv;
            $outrow->{dispd} += ($row->{dispd} - $prow->{dispd}) / $outdiv;
            $outrow->{hdispd} += ($row->{hdispd} - $prow->{hdispd}) / $outdiv;
            $outrow->{qdrops} += ($row->{qdrops} - $prow->{qdrops}) / $outdiv;
            $outrow->{queued} += ($row->{queued} - $prow->{queued}) / $outdiv;

            $out_proto_totals{$outproto}{cpu} += $cpu_stats->{$id} || 0;
            $out_proto_totals{$outproto}{qlen} += $row->{qlen};
            $out_proto_totals{$outproto}{wmark} += $row->{wmark};
            $out_proto_totals{$outproto}{handled} += ($row->{handled} - $prow->{handled}) / $outdiv;
            $out_proto_totals{$outproto}{dispd} += ($row->{dispd} - $prow->{dispd}) / $outdiv;
            $out_proto_totals{$outproto}{hdispd} += ($row->{hdispd} - $prow->{hdispd}) / $outdiv;
            $out_proto_totals{$outproto}{qdrops} += ($row->{qdrops} - $prow->{qdrops}) / $outdiv;
            $out_proto_totals{$outproto}{queued} += ($row->{queued} - $prow->{queued}) / $outdiv;

            $out_totals{qlen} += $row->{qlen};
            $out_totals{wmark} += $row->{wmark};
            $out_totals{handled} += ($row->{handled} - $prow->{handled}) / $outdiv;
            $out_totals{dispd} += ($row->{dispd} - $prow->{dispd}) / $outdiv;
            $out_totals{hdispd} += ($row->{hdispd} - $prow->{hdispd}) / $outdiv;
            $out_totals{qdrops} += ($row->{qdrops} - $prow->{qdrops}) / $outdiv;
            $out_totals{queued} += ($row->{queued} - $prow->{queued}) / $outdiv;
        }
        $out_totals{cpu} = $out_proto_totals{$outproto}{cpu}
            unless $out_totals{cpu};
    }

    my (@hdr, $hfmt, $fmt);
    if ($opts{p}) {
        @hdr = qw(Proto ID %CPU QLen WMark Handled Disp'd HDisp'd QDrop Queued);
        $hfmt = "\n%6s %3s %5s %5s %6s %8s %8s %8s %5s %8s\n";
        $fmt =    "%6s %3s %5.1f %5d %6d %8d %8d %8d %5d %8d\n";
        printf $hfmt, @hdr;
        for my $proto (sort keys %out) {
            print "\n";
            for my $id (sort keys %{$out{$proto}}) {
                my $row = $out{$proto}{$id};
                printf $fmt,
                    $proto, $id,
                    $row->{cpu}, $row->{qlen},
                    $row->{wmark}, $row->{handled},
                    $row->{dispd}, $row->{hdispd},
                    $row->{qdrops}, $row->{queued};
            }
            my $row = $out_proto_totals{$proto};
            printf $fmt,
                $proto, "Tot",
                $row->{cpu}, $row->{qlen},
                $row->{wmark}, $row->{handled},
                $row->{dispd}, $row->{hdispd},
                $row->{qdrops}, $row->{queued};
        }
        print "\n";
        my $row = \%out_totals;
        printf $fmt,
            "Total", "",
            $row->{cpu}, $row->{qlen},
            $row->{wmark}, $row->{handled},
            $row->{dispd}, $row->{hdispd},
            $row->{qdrops}, $row->{queued};
    } else {
        @hdr = qw(ID %CPU QLen WMark Handled Disp'd HDisp'd QDrop Queued);
        $hfmt = "\n%3s %5s %5s %6s %8s %8s %8s %5s %8s\n";
        $fmt =    "%3s %5.1f %5d %6d %8d %8d %8d %5d %8d\n";
        printf $hfmt, @hdr;
        my $proto = "-";
        for my $id (sort keys %{$out{$proto}}) {
            my $row = $out{$proto}{$id};
            printf $fmt,
                $id,
                $row->{cpu}, $row->{qlen},
                $row->{wmark}, $row->{handled},
                $row->{dispd}, $row->{hdispd},
                $row->{qdrops}, $row->{queued};
        }
        my $row = \%out_totals;
        printf $fmt,
            "Tot",
            $row->{cpu}, $row->{qlen},
            $row->{wmark}, $row->{handled},
            $row->{dispd}, $row->{hdispd},
            $row->{qdrops}, $row->{queued};
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
    my ($prev_netisr_stats, $prev_timestamp);
    local $SIG{'TERM'} = sub { $continue = 0 };
    local $SIG{'ALRM'} = \&timer_handler;

    &timer_handler;

    while ($continue) {
        if ($flag_collect_stats) {
            my $timestamp = time;
            my $netisr_stats = &collect_netisr_stats(\@proto_filter);
            my $cpu_stats = &collect_cpu_stats();

            if ($prev_netisr_stats) {
                &print_stats($timestamp - $prev_timestamp, $netisr_stats, $prev_netisr_stats, $cpu_stats);
            }
            $prev_netisr_stats = $netisr_stats;
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
