#!/usr/bin/env perl

# Copyright 2012 by Shoji KUMAGAI
# Apache License v2

# Read hexdump packet data from STDIN, write pcap format to STDOUT
# Usage: udpdump_to_pcap.rb < hexdump.txt > out.pcap

# Notes
# - UDP checksum is NOT calculated.
#   Recommend disabling checksum validation in viewer such as Wireshark.

# cf) See below about libpcap file format
# http://wiki.wireshark.org/Development/LibpcapFileFormat

# In pcap file, L2(MAC) is skipped by specifying Link-Layer Header to IPv4.
# So now support IPv4 only.
#
#   Link-Layer Header Types | TCPDUMP/LIBPCAP public repository
#   (http://www.tcpdump.org/linktypes.html)
#   LINKTYPE_IPV4 228 DLT_IPV4
#   Raw IPv4; the packet begins with an IPv4 header.

use strict;
use warnings;
use Time::Local;

sub print_hex {
    my ($hex, $label) = @_;
    # debug($hex, $label);
    print STDOUT pack("H*", $hex);
}

sub debug {
    my ($message, $label) =@_;
    print STDERR "======== $label ========\n" if $label;
    print STDERR "$message\n";
}

sub uint32_to_native_hex {
    # pack unsigned int as native bytes (little endian on x86 box)
    # and unpack as hex
    my ($value) = @_;
    return unpack("H*", pack("I*", $value));
}

# hex representation as network order with size of ``octets``
# ex) int_to_hex(1)     #=> "0001"
#     int_to_hex(32, 4) #=> "00000020"
sub int_to_hex {
    my ($value, $octets) = @_;
    !defined($octets) and $octets = 2;
    my $template = sprintf "%%0%dx", ($octets * 2);
    return sprintf $template, $value;
}

sub ipv4_to_hex {
    my ($ip_address) = @_;
    return join('', map { int_to_hex(int($_), 1) } split('\.', $ip_address));
}

sub udp_packet {
    my ($src_port, $dst_port, $data_length) = @_;
    my $udp_length = 8 + $data_length;
    $src_port = int_to_hex($src_port);
    $dst_port = int_to_hex($dst_port);
    my $udp_header = join('',
        $src_port,                # Source port
        $dst_port,                # Destination port
        int_to_hex($udp_length),  # length
        '0000', );                # checksum (NOT checked)
    return ($udp_header, $udp_length);
}

sub ipv4_packet {
    # 20 for ip header without options, 8 for udp header
    my ($src_ip, $dst_ip, $udp_length) = @_;
    my $ipv4_length = 20 + $udp_length;
    $src_ip = ipv4_to_hex($src_ip);
    $dst_ip = ipv4_to_hex($dst_ip);
    my $ipv4_header = join('',
        '4',                       # version (IP=4)
        '5',                       # IHL header length
        '00',                      # Type of Service
        int_to_hex($ipv4_length),  # Total length
        'afd4',                    # identification
        '4000',                    # flags (3bits) + Fragment offset (13bits)
        '40',                      # TTL
        '11',                      # Protocol UDP=17=0x11
        '0000',                    # header checksum
        $src_ip,                   # Source address
        $dst_ip, );                # Destination address
    return ($ipv4_header, $ipv4_length);
}

# This is function only using to parse ISO 8601 formatted timestamp string.
# Because there is no useful module as default for datetime parse.
sub parse_datetime {
    my ($datetime) = @_;
    if ($datetime =~ /(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/) {
        return timelocal($6, $5, $4, $3, $2 - 1, $1 - 1900);
    } else {
        die "Could not parse timestamp: $datetime\n";
    }
}

# In pcap packet, int's are represented as NATIVE byte order.
sub pcap_packet {
    my ($time_stamp, $ipv4_length) = @_;
    my ($datetime, $usec) = split('\.', $time_stamp);
    my $ts_sec = uint32_to_native_hex(int(parse_datetime($datetime)));
    my $ts_usec = uint32_to_native_hex(int($usec));

    my $packet_incl_len = uint32_to_native_hex($ipv4_length);
    return join('',
                $ts_sec,              # ts_sec (UNIX time)
                $ts_usec,             # ts_usec
                $packet_incl_len,     # incl_len (uint32)
                $packet_incl_len, );  # orig_len (uint32)
}

sub packet {
    my ($time_stamp, $src_ip, $src_port, $dst_ip, $dst_port, $data) = @_;
    # date is hex representation, so devided by two
    my ($udp_header, $udp_length) = udp_packet($src_port, $dst_port, (length($data) / 2));
    my ($ipv4_header, $ipv4_length) = ipv4_packet($src_ip, $dst_ip, $udp_length);
    my $packet_header = pcap_packet($time_stamp, $ipv4_length);

    print_hex($packet_header, 'packet_header');
    print_hex($ipv4_header, 'ipv4_header');
    print_hex($udp_header, 'udp_header');
    print_hex($data, 'data');
}

our $GLOBAL_HEADER =
    'd4c3b2a1' . '0200' . '0400' .  # magic + major + minor
    '00000000' . '00000000' .       # thiszone + sigfigs
    'ffff0000' .                    # snaplen
    'e4000000';                     # LINKTYPE_IPv4(228=e4)

sub convert {
    print_hex($GLOBAL_HEADER, 'global_header');
    while (my $line = <STDIN>) {
        chomp $line;
        my ($time_stamp, $hostname, $process_id,
            $src_ip, $src_port, $dst_ip, $dst_port, $data) = split(',', $line);
        packet($time_stamp, $src_ip, $src_port, $dst_ip, $dst_port, $data);
    }
}

sub main {
    convert();
}

main if (__FILE__ eq $0);
