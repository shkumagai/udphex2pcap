#!/usr/bin/env escript
%% -*- erlang -*-

-module(stdin).

-export([main/1]).


main(_) ->
    convert().

convert() ->
    GlobalHeader = lists:concat(
                     ["d4c3b2a1",  %% magic
                      "0200",      %% major
                      "0400",      %% minor
                      "00000000",  %% thiszone
                      "00000000",  %% sigfigs
                      "ffff0000",  %% snaplen
                      "e4000000"]  %% LINKTYPE_IPv4(228=e4)
                    ),
    print_hex(GlobalHeader, "global_header"),
    loop(io:get_line(standard_io, "")).

loop(eof) -> ok;
loop(Line) ->
    StripedLine = re:replace(Line, "\n", "", [{return, list}]),
    [TimeStamp, _, _, SrcIp, SrcPort, DstIp, DstPort, Data] =
        string:tokens(StripedLine, ","),
    packet(TimeStamp, SrcIp, SrcPort, DstIp, DstPort, Data),
    loop(io:get_line(standard_io, "")).

packet(TimeStamp, SrcIp, SrcPort, DstIp, DstPort, Data) ->
    %% data is hex representation, so devided by two
    {UdpHeader, UdpLength} = udp_packet(SrcPort, DstPort, string:len(Data) div 2),
    {IPv4Header, IPv4Length} = ipv4_packet(SrcIp, DstIp, UdpLength),
    PacketHeader = pcap_packet(TimeStamp, IPv4Length),
    print_hex(PacketHeader, "packet_header"),
    print_hex(IPv4Header, "ipv4_header"),
    print_hex(UdpHeader, "udp_header"),
    print_hex(Data, "data").

pcap_packet(TimeStamp, IPv4Length) ->
    [DateTime, Usec] = string:tokens(TimeStamp, "."),
    {ok, Reg} =
        re:compile("^(\\d{4})-(\\d{2})-(\\d{2})T(\\d{2}):(\\d{2}):(\\d{2})$"),
    case re:run(DateTime, Reg, [{capture, all_but_first, list}]) of
        {match, [Year, Month, Day, Hour, Min, Sec]} ->
            EpochTime = calendar:datetime_to_gregorian_seconds(
                          {{list_to_integer(Year),
                            list_to_integer(Month),
                            list_to_integer(Day)},
                           {list_to_integer(Hour),
                            list_to_integer(Min),
                            list_to_integer(Sec)}}),
            EpochOrigin = calendar:datetime_to_gregorian_seconds(
                            {{1970,1,1},{9,0,0}}),
            EpochDiff = EpochTime - EpochOrigin,
            TsSec = to_native(to_hex(EpochDiff, 4)),
            TsUsec = to_native(to_hex(list_to_integer(Usec), 4)),
            PacketInclLen = to_native(to_hex(IPv4Length, 4)),
            lists:concat(
              [TsSec,            %% ts_sec (UNIX time)
               TsUsec,           %% ts_usec
               PacketInclLen,    %% incl_len (uint32)
               PacketInclLen]);  %% orig_len (uint32)
        nomatch ->
            io:write("Invalid DateTime format: ~s~n", [TimeStamp])
    end.

ipv4_packet(SrcIp, DstIp, Length) ->
    %% 20 for ip header without option, 8 for udp header
    IPv4Length = 20 + Length,
    IPv4Header = lists:concat(
                   ["4",                   %% version (IP=4)
                    "5",                   %% IHL header length
                    "00",                  %% Type of Service
                    to_hex(IPv4Length),    %% Total length
                    "afd4",                %% identification
                    "4000",                %% flags(3bits) + Fragment offset(13bits)
                    "40",                  %% TTL
                    "11",                  %% Protcol UDP=17=0x11
                    "0000",                %% header checksum
                    ipv4_to_hex(SrcIp),    %% Source address
                    ipv4_to_hex(DstIp)]),  %% Destination address
    {IPv4Header, IPv4Length}.

udp_packet(SrcPort, DstPort, Length) ->
    UdpLength = 8 + Length,
    UdpHeader = lists:concat(
                  [to_hex(list_to_integer(SrcPort)),  %% Source port
                   to_hex(list_to_integer(DstPort)),  %% Destination port
                   to_hex(UdpLength),                 %% length
                   "0000"]),                          %% checksum (NOT checked)
    {UdpHeader, UdpLength}.

ipv4_to_hex(IpAddress) ->
    lists:concat(
      [to_hex(list_to_integer(X), 1) || X <- string:tokens(IpAddress, ".")]).

dehex(C) when C >= $0, C =< $9 ->
    C - $0;
dehex(C) when C >= $a, C =< $f ->
    C - $a + 10;
dehex(C) when C >= $A, C =< $F ->
    C - $A + 10.

hexdigit(C) when C >= 0, C =< 9 ->
    C + $0;
hexdigit(C) when C =< 15 ->
    C + $a - 10.

to_bin(L) ->
    to_bin(L, []).

to_bin([], Acc) ->
    iolist_to_binary(lists:reverse(Acc));
to_bin([C1, C2 | Rest], Acc) ->
    to_bin(Rest, [(dehex(C1) bsl 4) bor dehex(C2) | Acc]).

%% hex representation as network order with size of ``octets``
%% ex) to_hex(1)      #=> "0001"
%%     to_hex(32, 4)  #=> "00000020"
to_hex(0) ->
    to_hex(0, 2);
to_hex(I) when is_integer(I), I > 0 ->
    to_hex(I, 2).

to_hex(0, Octets) ->
    to_hex(0, "0", Octets);
to_hex(I, Octets) when is_integer(I), I > 0 ->
    to_hex(I, [], Octets).

to_hex(0, Acc, Octets) ->
    string:right(Acc, Octets * 2, $0);
to_hex(I, Acc, Octets) ->
    to_hex(I bsr 4, [hexdigit(I band 15) | Acc], Octets).

to_native(L) ->
    to_native(L, []).

to_native([], Acc) ->
    Acc;
to_native([C1, C2 | Rest], Acc) ->
    to_native(Rest, [C1, C2 | Acc]).

print_hex(Data, Label) ->
    io:format(standard_error, "~s~n", [Label]),
    io:format("~s", [to_bin(Data)]).
