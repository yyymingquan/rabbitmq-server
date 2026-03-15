%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Copyright (c) 2007-2026 Broadcom. All Rights Reserved. The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries. All rights reserved.
%%

-module(rabbit_stomp_frame).

-include("rabbit_stomp_frame.hrl").
-include("rabbit_stomp_headers.hrl").

-export([parse/2, initial_state/0, initial_state/1]).
-export([header/2, header/3,
         boolean_header/2, boolean_header/3,
         integer_header/2, integer_header/3,
         binary_header/2, binary_header/3]).
-export([stream_offset_header/1, stream_filter_header/1]).
-export([serialize/1, serialize/2]).

initial_state() -> {none, ?DEFAULT_STOMP_PARSER_CONFIG}.
initial_state(Config) -> {none, Config}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% STOMP 1.0/1.1/1.2 frame syntax
%%
%%  Rabbit modifications:
%%  - CR LF is equivalent to LF in all element terminators (eol)
%%  - Escape codes for header names and values include \r for CR
%%    and CR is not allowed
%%  - Header names and values are not limited to UTF-8 strings
%%  - Header values may contain unescaped colons
%%
%%  frame_seq   ::= *(noise frame)
%%  noise       ::= *(NUL | eol)
%%  eol         ::= LF | CR LF
%%  frame       ::= cmd hdrs body NUL
%%  body        ::= *OCTET
%%  cmd         ::= 1*NOTEOL eol
%%  hdrs        ::= *hdr eol
%%  hdr         ::= hdrname COLON hdrvalue eol
%%  hdrname     ::= 1*esc_char
%%  hdrvalue    ::= *esc_char
%%  esc_char    ::= HDROCT | BACKSLASH ESCCODE
%%
%%  OCTET       ::= '00'x..'FF'x
%%  NUL         ::= '00'x
%%  LF          ::= '\n'
%%  CR          ::= '\r'
%%  NOTEOL      ::= OCTET - (CR | LF)
%%  BACKSLASH   ::= '\\'
%%  ESCCODE     ::= 'c' | 'n' | 'r' | BACKSLASH
%%  COLON       ::= ':'
%%  HDROCT      ::= NOTEOL - (COLON | BACKSLASH)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% Frame characters
-define(NUL,   0).
-define(CR,    $\r).
-define(LF,    $\n).
-define(BSL,   $\\).
-define(COLON, $:).

%% Header escape codes
-define(LF_ESC,    $n).
-define(BSL_ESC,   $\\).
-define(COLON_ESC, $c).
-define(CR_ESC,    $r).

%% Command lookup: binary -> atom for known STOMP commands.
%% Unknown commands pass through as binaries.
-define(KNOWN_COMMANDS,
        #{<<"SEND">>        => 'SEND',
          <<"SUBSCRIBE">>   => 'SUBSCRIBE',
          <<"UNSUBSCRIBE">> => 'UNSUBSCRIBE',
          <<"STOMP">>       => 'STOMP',
          <<"CONNECT">>     => 'CONNECT',
          <<"CONNECTED">>   => 'CONNECTED',
          <<"DISCONNECT">>  => 'DISCONNECT',
          <<"BEGIN">>       => 'BEGIN',
          <<"COMMIT">>      => 'COMMIT',
          <<"ABORT">>       => 'ABORT',
          <<"ACK">>         => 'ACK',
          <<"NACK">>        => 'NACK',
          <<"MESSAGE">>     => 'MESSAGE',
          <<"RECEIPT">>     => 'RECEIPT',
          <<"ERROR">>       => 'ERROR'}).

%% The longest known STOMP command is UNSUBSCRIBE (11 bytes).
%% Allow some headroom for unknown commands but bound memory usage.
-define(MAX_COMMAND_LENGTH, 32).

%% Parser state
-record(ps, {acc     = [] :: [byte()],
             acc_len = 0  :: non_neg_integer(),
             cmd          :: atom() | binary() | undefined,
             hdrs    = [] :: [{string(), string()}],
             hdrname      :: string() | undefined,
             config       :: #stomp_parser_config{}}).

%%
%% Public API
%%

parse(Content, {resume, Continuation}) -> Continuation(Content);
parse(Content, {none, Config})         -> parser(Content, noise, #ps{config = Config}).

%%
%% Incremental state machine parser
%%
%% Phases: noise | command | headers | hdrname | hdrvalue
%% Body parsing is handled separately by parse_body/2.
%%

more(Continuation) -> {more, {resume, Continuation}}.

%% --- Need more data ---
parser(<<>>,                        Phase,  S) -> more(fun(Rest) -> parser(Rest, Phase, S) end);
parser(<<?CR>>,                     Phase,  S) -> more(fun(Rest) -> parser(<<?CR, Rest/binary>>, Phase, S) end);

%% --- CR LF normalization ---
parser(<<?CR, ?LF,   Rest/binary>>, Phase,  S) -> parser(<<?LF, Rest/binary>>, Phase, S);
parser(<<?CR, Ch:8, _Rest/binary>>, Phase, _S) -> {error, {unexpected_chars(Phase), [?CR, Ch]}};

%% --- Escape processing (header names and values only) ---
parser(<<?BSL>>,                    Phase,  S)
  when Phase =:= hdrname;
       Phase =:= hdrvalue -> more(fun(Rest) -> parser(<<?BSL, Rest/binary>>, Phase, S) end);
parser(<<?BSL, Ch:8, Rest/binary>>, Phase,  S)
  when Phase =:= hdrname;
       Phase =:= hdrvalue -> unescape(Ch, fun(Ech) -> parser(Rest, Phase, accum(Ech, S)) end);

%% --- Noise: skip NULs and LFs between frames ---
parser(<<?NUL, Rest/binary>>, noise, S) -> parser(Rest, noise, S);
parser(<<?LF,  Rest/binary>>, noise, S) -> parser(Rest, noise, S);
parser(Rest,                  noise, S) -> parser(Rest, command, S#ps{acc = [], acc_len = 0});

%% --- Command: accumulate bytes until LF ---
parser(<<?LF,        Rest/binary>>, command, S) -> goto(command, headers, Rest, S);
parser(<<Ch:8,       Rest/binary>>, command, S = #ps{acc_len = Len}) ->
    case Len >= ?MAX_COMMAND_LENGTH of
        true  -> {error, {command_too_long, ?MAX_COMMAND_LENGTH}};
        false -> parser(Rest, command, accum(Ch, S))
    end;

%% --- Headers: LF means end of headers (start body), otherwise start a header name ---
parser(<<?LF,        Rest/binary>>, headers, S) -> goto(headers, body, Rest, S);
parser(Rest,                        headers, S) -> goto(headers, hdrname, Rest, S);

%% --- Header name: accumulate until COLON or LF ---
parser(<<?COLON,     Rest/binary>>, hdrname, S) -> goto(hdrname, hdrvalue, Rest, S);
parser(<<?LF,       _Rest/binary>>, hdrname, #ps{acc = Acc}) ->
    {error, {header_no_value, lists:reverse(Acc)}};
parser(<<Ch:8,       Rest/binary>>, hdrname, S = #ps{acc_len = Len,
                                                      config = #stomp_parser_config{
                                                                  max_header_length = Max}}) ->
    case Len >= Max of
        true  -> {error, {max_header_length, Max}};
        false -> parser(Rest, hdrname, accum(Ch, S))
    end;

%% --- Header value: accumulate until LF ---
parser(<<?LF,        Rest/binary>>, hdrvalue, S) -> goto(hdrvalue, headers, Rest, S);
parser(<<Ch:8,       Rest/binary>>, hdrvalue, S = #ps{acc_len = Len,
                                                       config = #stomp_parser_config{
                                                                   max_header_length = Max}}) ->
    case Len >= Max of
        true  -> {error, {max_header_length, Max}};
        false -> parser(Rest, hdrvalue, accum(Ch, S))
    end.

%%
%% State transitions
%%

goto(command, headers, Rest, S = #ps{acc = Acc}) ->
    CmdBin = list_to_binary(lists:reverse(Acc)),
    Cmd = maps:get(CmdBin, ?KNOWN_COMMANDS, CmdBin),
    parser(Rest, headers, S#ps{cmd = Cmd, hdrs = []});

goto(headers, body, Rest, S) ->
    parse_body(Rest, S);

goto(headers, hdrname, Rest, S = #ps{hdrs = Headers,
                                     config = #stomp_parser_config{
                                                 max_headers = MaxHeaders}}) ->
    case length(Headers) >= MaxHeaders of
        true  -> {error, {max_headers, MaxHeaders}};
        false -> parser(Rest, hdrname, S#ps{acc = [], acc_len = 0})
    end;

goto(hdrname, hdrvalue, Rest, S = #ps{acc = Acc}) ->
    parser(Rest, hdrvalue, S#ps{acc = [], acc_len = 0,
                                hdrname = lists:reverse(Acc)});

goto(hdrvalue, headers, Rest, S = #ps{acc = Acc, hdrs = Headers, hdrname = HdrName}) ->
    parser(Rest, headers, S#ps{hdrs = insert_header(Headers, HdrName,
                                                    lists:reverse(Acc))}).

%%
%% Helpers
%%

unexpected_chars(noise)    -> unexpected_chars_between_frames;
unexpected_chars(command)  -> unexpected_chars_in_command;
unexpected_chars(hdrname)  -> unexpected_chars_in_header;
unexpected_chars(hdrvalue) -> unexpected_chars_in_header;
unexpected_chars(_)        -> unexpected_chars.

accum(Ch, S = #ps{acc = Acc, acc_len = Len}) ->
    S#ps{acc = [Ch | Acc], acc_len = Len + 1}.

unescape(?LF_ESC,    Fun) -> Fun(?LF);
unescape(?BSL_ESC,   Fun) -> Fun(?BSL);
unescape(?COLON_ESC, Fun) -> Fun(?COLON);
unescape(?CR_ESC,    Fun) -> Fun(?CR);
unescape(Ch,        _Fun) -> {error, {bad_escape, [?BSL, Ch]}}.

%% First occurrence of a header name wins
insert_header(Headers, Name, Value) ->
    case lists:keymember(Name, 1, Headers) of
        true  -> Headers;
        false -> [{Name, Value} | Headers]
    end.

%%
%% Body parsing
%%

parse_body(Content, #ps{cmd = Cmd, hdrs = Hdrs,
                        config = #stomp_parser_config{
                                   max_body_length = MaxBodyLength}}) ->
    Frame = #stomp_frame{command = Cmd, headers = Hdrs},
    case Cmd of
        'SEND' ->
            case integer_header(Frame, ?HEADER_CONTENT_LENGTH, unknown) of
                ContentLength when is_integer(ContentLength),
                                   ContentLength > MaxBodyLength ->
                    {error, {max_body_length, ContentLength}};
                ContentLength when is_integer(ContentLength) ->
                    parse_known_body(Content, Frame, [], ContentLength);
                _ ->
                    parse_unknown_body(Content, Frame, [], MaxBodyLength)
            end;
        _ ->
            parse_unknown_body(Content, Frame, [], MaxBodyLength)
    end.

-define(MORE_BODY(Content, Frame, Chunks, Remaining),
            Chunks1 = finalize_chunk(Content, Chunks),
            more(fun(Rest) -> ?FUNCTION_NAME(Rest, Frame, Chunks1, Remaining) end)).

parse_unknown_body(Content, Frame, Chunks, Remaining) ->
    case firstnull(Content) of
        -1 ->
            ChunkSize = byte_size(Content),
            case ChunkSize > Remaining of
                true  -> {error, {max_body_length, unknown}};
                false -> ?MORE_BODY(Content, Frame, Chunks, Remaining - ChunkSize)
            end;
        Pos ->
            case Pos > Remaining of
                true  -> {error, {max_body_length, unknown}};
                false -> finish_body(Content, Frame, Chunks, Pos)
            end
    end.

parse_known_body(Content, Frame, Chunks, Remaining) ->
    Size = byte_size(Content),
    case Remaining >= Size of
        true  -> ?MORE_BODY(Content, Frame, Chunks, Remaining - Size);
        false -> finish_body(Content, Frame, Chunks, Remaining)
    end.

finish_body(Content, Frame, Chunks, Pos) ->
    <<Chunk:Pos/binary, 0, Rest/binary>> = Content,
    Body = finalize_chunk(Chunk, Chunks),
    {ok, Frame#stomp_frame{body_iolist_rev = Body}, Rest}.

finalize_chunk(<<>>,  Chunks) -> Chunks;
finalize_chunk(Chunk, Chunks) -> [Chunk | Chunks].

firstnull(Content) -> firstnull(Content, 0).

firstnull(<<>>,                _N) -> -1;
firstnull(<<0,  _Rest/binary>>, N) -> N;
firstnull(<<_Ch, Rest/binary>>, N) -> firstnull(Rest, N + 1).

%%
%% Header accessors
%%

default_value({ok, Value}, _DefaultValue) -> Value;
default_value(not_found,    DefaultValue) -> DefaultValue.

header(#stomp_frame{headers = Headers}, Key) ->
    case lists:keysearch(Key, 1, Headers) of
        {value, {_, Str}} -> {ok, Str};
        _                 -> not_found
    end.

header(F, K, D) -> default_value(header(F, K), D).

boolean_header(#stomp_frame{headers = Headers}, Key) ->
    case lists:keysearch(Key, 1, Headers) of
        {value, {_, "true"}}  -> {ok, true};
        {value, {_, "false"}} -> {ok, false};
        {value, {_, "True"}}  -> {ok, true};
        {value, {_, "False"}} -> {ok, false};
        _                     -> not_found
    end.

boolean_header(F, K, D) -> default_value(boolean_header(F, K), D).

internal_integer_header(Headers, Key) ->
    case lists:keysearch(Key, 1, Headers) of
        {value, {_, Str}} -> {ok, list_to_integer(string:strip(Str))};
        _                 -> not_found
    end.

integer_header(#stomp_frame{headers = Headers}, Key) ->
    internal_integer_header(Headers, Key).

integer_header(F, K, D) -> default_value(integer_header(F, K), D).

binary_header(F, K) ->
    case header(F, K) of
        {ok, Str} -> {ok, list_to_binary(Str)};
        not_found -> not_found
    end.

binary_header(F, K, D) -> default_value(binary_header(F, K), D).

stream_offset_header(F) ->
    case binary_header(F, ?HEADER_X_STREAM_OFFSET) of
        {ok, <<"first">>}                    -> {longstr, <<"first">>};
        {ok, <<"last">>}                     -> {longstr, <<"last">>};
        {ok, <<"next">>}                     -> {longstr, <<"next">>};
        {ok, <<"offset=", V/binary>>}        -> {long, binary_to_integer(V)};
        {ok, <<"timestamp=", V/binary>>}     -> {timestamp, binary_to_integer(V)};
        _                                    -> not_found
    end.

stream_filter_header(F) ->
    case binary_header(F, ?HEADER_X_STREAM_FILTER) of
        {ok, Str} ->
            {array, lists:reverse(
                      lists:foldl(fun(V, Acc) ->
                                          [{longstr, V} | Acc]
                                  end,
                                  [],
                                  binary:split(Str, <<",">>, [global])))};
        not_found ->
            not_found
    end.

%%
%% Serialization
%%

serialize(Frame) ->
    serialize(Frame, true).

serialize(Frame, true) ->
    serialize(Frame, false) ++ [?LF];
serialize(#stomp_frame{command = Command,
                       headers = Headers,
                       body_iolist_rev = BodyFragments}, false) ->
    Len = iolist_size(BodyFragments),
    [serialize_command(Command), ?LF,
     lists:map(fun serialize_header/1,
               lists:keydelete(?HEADER_CONTENT_LENGTH, 1, Headers)),
     if
         Len > 0 -> [?HEADER_CONTENT_LENGTH ++ ":", integer_to_list(Len), ?LF];
         true    -> []
     end,
     ?LF, case BodyFragments of
              _ when is_binary(BodyFragments) -> BodyFragments;
              _ -> lists:reverse(BodyFragments)
          end, 0].

serialize_command(Command) when is_atom(Command) ->
    atom_to_binary(Command, utf8);
serialize_command(Command) -> Command.

serialize_header({K, V}) when is_integer(V) -> hdr(escape(K), integer_to_list(V));
serialize_header({K, V}) when is_boolean(V) -> hdr(escape(K), boolean_to_list(V));
serialize_header({K, V}) when is_list(V)    -> hdr(escape(K), escape(V)).

boolean_to_list(true) -> "true";
boolean_to_list(_)    -> "false".

hdr(K, V) -> [K, ?COLON, V, ?LF].

escape(Str) -> [escape1(Ch) || Ch <- Str].

escape1(?COLON) -> [?BSL, ?COLON_ESC];
escape1(?BSL)   -> [?BSL, ?BSL_ESC];
escape1(?LF)    -> [?BSL, ?LF_ESC];
escape1(?CR)    -> [?BSL, ?CR_ESC];
escape1(Ch)     -> Ch.
