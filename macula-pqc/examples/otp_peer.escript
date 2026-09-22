#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% The OTP side of `scripts/otp-interop.sh`: one TLS 1.3 connection using
%% OTP's own `ssl`, offering ONLY the groups it is given. Driven by
%% `examples/otp_interop.rs`, which is the other side.
%%
%%   otp_peer.escript dial <port> <groups> <certdir>
%%   otp_peer.escript serve <groups> <certdir>     prints "port <n>" first
%%
%% <groups> is comma-separated OTP group names. Prints "ok" and exits 0
%% when the handshake completed and "ping"/"pong" crossed it; otherwise
%% prints "error <reason>" and exits 1.

main(["dial", Port, Groups, Dir]) ->
    run(fun() -> dial(list_to_integer(Port), groups(Groups), Dir) end);
main(["serve", Groups, Dir]) ->
    run(fun() -> serve(groups(Groups), Dir) end).

run(F) ->
    {ok, _} = application:ensure_all_started(ssl),
    try F() of
        ok ->
            io:format("ok~n"),
            halt(0)
    catch
        Class:Reason ->
            io:format("error ~0p~n", [{Class, Reason}]),
            halt(1)
    end.

groups(Csv) ->
    [list_to_atom(G) || G <- string:split(Csv, ",", all)].

common(Groups) ->
    [{versions, ['tlsv1.3']}, {supported_groups, Groups}, {active, false}, binary].

dial(Port, Groups, Dir) ->
    {ok, Ca} = file:read_file(filename:join(Dir, "ca.der")),
    Opts = common(Groups) ++
        [{verify, verify_peer}, {cacerts, [Ca]}, {server_name_indication, "localhost"}],
    {ok, S} = ssl:connect("127.0.0.1", Port, Opts, 15000),
    ok = ssl:send(S, <<"ping">>),
    {ok, <<"pong">>} = ssl:recv(S, 4, 15000),
    ssl:close(S).

serve(Groups, Dir) ->
    {ok, Cert} = file:read_file(filename:join(Dir, "server.der")),
    {ok, Key} = file:read_file(filename:join(Dir, "server.key.der")),
    Opts = common(Groups) ++
        [{certs_keys, [#{cert => Cert, key => {'PrivateKeyInfo', Key}}]}, {reuseaddr, true}],
    {ok, L} = ssl:listen(0, Opts),
    {ok, {_, Port}} = ssl:sockname(L),
    io:format("port ~b~n", [Port]),
    {ok, T} = ssl:transport_accept(L, 15000),
    {ok, S} = ssl:handshake(T, 15000),
    {ok, <<"ping">>} = ssl:recv(S, 4, 15000),
    ok = ssl:send(S, <<"pong">>),
    ssl:close(S).
