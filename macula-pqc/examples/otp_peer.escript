#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% The OTP side of `scripts/otp-interop.sh`: one TLS 1.3 connection using
%% OTP's own `ssl`, offering ONLY the groups and signature algorithms it is
%% given. Driven by `examples/otp_interop.rs`, which is the other side.
%%
%%   otp_peer.escript dial <port> <groups> <sigalgs> <certdir>
%%   otp_peer.escript serve <groups> <identity> <certdir>   prints "port <n>" first
%%   otp_peer.escript verify_cert <certdir>
%%
%% <groups> and <sigalgs> are comma-separated OTP names. <identity> names the
%% files the server presents: <identity>.der and <identity>.key.der. dial
%% trusts exactly the certificate in ours.der, which is self-signed, as a
%% macula station's is, and accepts the peer only because it is that one.
%% A trusted certificate is a trust anchor, so OTP never checks its own
%% signature; the server's CertificateVerify, under the key it carries, is
%% what dial checks. verify_cert checks ours.der's own signature with its own
%% key, separately.
%%
%% Prints "ok" and exits 0 when the handshake completed and "ping"/"pong"
%% crossed it, or the certificate verified; otherwise prints
%% "error <reason>" and exits 1.

-include_lib("public_key/include/public_key.hrl").

main(["dial", Port, Groups, SigAlgs, Dir]) ->
    run(fun() -> dial(list_to_integer(Port), names(Groups), names(SigAlgs), Dir) end);
main(["serve", Groups, Identity, Dir]) ->
    run(fun() -> serve(names(Groups), Identity, Dir) end);
main(["verify_cert", Dir]) ->
    run(fun() -> verify_cert(Dir) end).

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

names(Csv) ->
    [list_to_atom(N) || N <- string:split(Csv, ",", all)].

common(Groups) ->
    [{versions, ['tlsv1.3']}, {supported_groups, Groups}, {active, false}, binary].

dial(Port, Groups, SigAlgs, Dir) ->
    {ok, Ours} = file:read_file(filename:join(Dir, "ours.der")),
    Opts = common(Groups) ++
        [{verify, verify_peer}, {cacerts, [Ours]}, {signature_algs, SigAlgs},
         {verify_fun, {fun pinned/3, Ours}}, {server_name_indication, "localhost"}],
    {ok, S} = ssl:connect("127.0.0.1", Port, Opts, 15000),
    ok = ssl:send(S, <<"ping">>),
    {ok, <<"pong">>} = ssl:recv(S, 4, 15000),
    ssl:close(S).

%% A self-signed peer is accepted when it is exactly the certificate trusted, as
%% a pinned one is. Its own signature is not checked here or by OTP: see
%% verify_cert.
pinned(Cert, {bad_cert, selfsigned_peer}, Ours) ->
    verdict(public_key:pkix_encode('OTPCertificate', Cert, otp) =:= Ours, Ours);
pinned(_Cert, {bad_cert, _} = Reason, _Ours) ->
    {fail, Reason};
pinned(_Cert, {extension, _}, Ours) ->
    {unknown, Ours};
pinned(_Cert, valid, Ours) ->
    {valid, Ours};
pinned(_Cert, valid_peer, Ours) ->
    {valid, Ours}.

verdict(true, Ours) -> {valid, Ours};
verdict(false, _Ours) -> {fail, not_the_pinned_certificate}.

serve(Groups, Identity, Dir) ->
    {ok, Cert} = file:read_file(filename:join(Dir, Identity ++ ".der")),
    {ok, Key} = file:read_file(filename:join(Dir, Identity ++ ".key.der")),
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

%% The certificate's signature over its tbsCertificate, under the key it carries,
%% checked by OTP's public_key.
verify_cert(Dir) ->
    {ok, Der} = file:read_file(filename:join(Dir, "ours.der")),
    #'OTPCertificate'{tbsCertificate = Tbs} = public_key:pkix_decode_cert(Der, otp),
    #'OTPSubjectPublicKeyInfo'{subjectPublicKey = Key} = Tbs#'OTPTBSCertificate'.subjectPublicKeyInfo,
    true = public_key:pkix_verify(Der, Key),
    ok.
