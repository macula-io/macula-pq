#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% The OTP side of `scripts/otp-interop.sh` for ML-DSA: OTP's own
%% `crypto` generating, deriving, signing and verifying. Driven by
%% `examples/otp_interop.rs`, which is the other side. Every key, message
%% and signature passes through a file as raw bytes.
%%
%%   otp_mldsa_peer.escript keygen <alg> <pk-out> <sk-out>
%%   otp_mldsa_peer.escript derive <alg> <expanded-sk-in> <pk-out>
%%   otp_mldsa_peer.escript sign   <alg> expandedkey|seed <key-in> <msg-in> <sig-out>
%%   otp_mldsa_peer.escript verify <alg> <pk-in> <msg-in> <sig-in>
%%
%% <alg> is mldsa44, mldsa65 or mldsa87. `verify` prints "valid" or
%% "invalid"; the others print "ok". Any failure prints "error <reason>"
%% and exits 1.

main(Args) ->
    try run(Args) of
        Out ->
            io:format("~s~n", [Out]),
            halt(0)
    catch
        Class:Reason ->
            io:format("error ~0p~n", [{Class, Reason}]),
            halt(1)
    end.

run(["keygen", Alg, PkOut, SkOut]) ->
    {Pub, Priv} = crypto:generate_key(alg(Alg), []),
    ok = file:write_file(PkOut, Pub),
    ok = file:write_file(SkOut, Priv),
    "ok";
run(["derive", Alg, SkIn, PkOut]) ->
    {Pub, _} = crypto:generate_key(alg(Alg), [], read(SkIn)),
    ok = file:write_file(PkOut, Pub),
    "ok";
run(["sign", Alg, Form, KeyIn, MsgIn, SigOut]) ->
    Key = {form(Form), read(KeyIn)},
    ok = file:write_file(SigOut, crypto:sign(alg(Alg), none, read(MsgIn), Key)),
    "ok";
run(["verify", Alg, PkIn, MsgIn, SigIn]) ->
    verdict(crypto:verify(alg(Alg), none, read(MsgIn), read(SigIn), read(PkIn))).

alg("mldsa44") -> mldsa44;
alg("mldsa65") -> mldsa65;
alg("mldsa87") -> mldsa87.

form("expandedkey") -> expandedkey;
form("seed") -> seed.

verdict(true) -> "valid";
verdict(false) -> "invalid".

read(Path) ->
    {ok, Bin} = file:read_file(Path),
    Bin.
