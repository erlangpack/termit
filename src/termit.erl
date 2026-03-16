%%
%% @doc Serialize an Erlang term to signed encrypted binary and
%% deserialize it back ensuring it's not been forged.
%%
%% Some code extracted from
%%   https://github.com/mochi/mochiweb/blob/master/src/mochiweb_session.erl.
%%

-module(termit).
-author('Vladimir Dronnikov <dronnikov@gmail.com>').

-export([
    check_expired/1,
    decode/2,
    decode_base64/2,
    encode/2,
    encode_base64/2,
    expires_by/2,
    expiring/2,
    issue_token/2,
    issue_token/3,
    verify_token/2
  ]).

-define(MAGIC_V2, "TRM2").
-define(IV_SIZE, 12).
-define(TAG_SIZE, 16).

%%
%% -----------------------------------------------------------------------------
%% @doc Given a result of encode/2, i.e. a signed encrypted binary,
%% check the signature, uncrypt and deserialize into original term.
%% -----------------------------------------------------------------------------
%%

-spec decode(
    Cipher :: binary(),
    Secret :: binary()) ->
  {ok, Term :: any()} |
  {error, forged} |
  {error, badarg}.

decode(<<?MAGIC_V2, IV:12/binary, Tag:16/binary, Ciphertext/binary>>, Secret) ->
    EncKey = key(Secret),
    case crypto:crypto_one_time_aead(aes_256_gcm, EncKey, IV, Ciphertext, <<?MAGIC_V2>>, Tag, false) of
        Plaintext when is_binary(Plaintext) ->
            try binary_to_term(Plaintext, [safe]) of
                Term ->
                    {ok, Term}
            catch error:badarg ->
                      {error, badarg}
            end;
        error ->
            {error, invalid_token}
    end;
%% N.B. unmatched binaries are forged
decode(Bin, _) when is_binary(Bin) ->
  {error, forged}.

-spec encode(
    Term :: any(),
    Secret :: binary()) ->
  Cipher :: binary().

encode(Term, Secret) ->
    Key = key(Secret),
    IV = rand_bytes(?IV_SIZE),
    Plaintext = term_to_binary(Term, [compressed, {minor_version, 1}]),
    {Ciphertext, Tag} = crypto:crypto_one_time_aead(aes_256_gcm, Key, IV, Plaintext, <<?MAGIC_V2>>, ?TAG_SIZE, true),
    <<?MAGIC_V2, IV/binary, Tag/binary, Ciphertext/binary>>.

key(Secret) ->
    crypto:mac(hmac, sha256, Secret, <<"termit-enc-v2">>).

%%
%% -----------------------------------------------------------------------------
%% Conversion helpers
%% -----------------------------------------------------------------------------
%%

encode_base64(Term, Secret) ->
  termit_base64url:encode(encode(Term, Secret)).

decode_base64(undefined, _) ->
  {error, forged};
decode_base64(Bin, Secret) when is_binary(Bin) ->
  try termit_base64url:decode(Bin) of
      <<?MAGIC_V2, _/binary>> = Decoded ->
          decode(Decoded, Secret);
      PossibleOldtoken ->
          termit_v1:decode(PossibleOldtoken, Secret)
  catch _:_ ->
    {error, forged}
  end.

%%
%% -----------------------------------------------------------------------------
%% Expiration helpers
%% -----------------------------------------------------------------------------
%%

-spec timestamp(
    Delta :: integer()) ->
  integer().

timestamp(Delta) when is_integer(Delta) ->
  erlang:system_time(second) + Delta.

expiring(Term, Ttl) ->
  expires_by(Term, timestamp(Ttl)).

expires_by(Term, When) ->
  {expires, When, Term}.

check_expired(Term) ->
  check_expired(Term, timestamp(0)).

check_expired({expires, ExpiresAt, Data}, Now) ->
  case ExpiresAt > Now of
    true -> {ok, Data};
    false -> {error, expired}
  end;
check_expired(_, _) ->
  {error, badarg}.

%%
%% -----------------------------------------------------------------------------
%% Token helpers
%% -----------------------------------------------------------------------------
%%

-spec issue_token(
    Term :: any(),
    Secret :: binary(),
    Ttl :: non_neg_integer()) ->
  Token :: binary().

issue_token(Term, Secret, Ttl) ->
  encode_base64(expiring(Term, Ttl), Secret).

-spec issue_token(
    Term :: any(),
    Secret :: binary()) ->
 Token :: binary().

issue_token(Term, Secret) ->
  encode_base64(Term, Secret).


-spec verify_token(
    Token :: binary(),
    Secret :: binary()) ->
  {ok, Term :: any()} |
  {error, forged} |  % token forged
  {error, badarg} |  % token not created with issue_token/3
  {error, expired}.  % token no longer valid

verify_token(Token, Secret) ->
  case decode_base64(Token, Secret) of
    {ok, {expires, _ExpiresAt, _Data}=Decoded} -> check_expired(Decoded);
    {ok, Decoded} -> {ok, Decoded};
    Error -> Error
  end.


%% @doc Return N random bytes. This falls back to the pseudo random version of rand_uniform
%% if strong_rand_bytes fails.
-spec rand_bytes( Length :: pos_integer() ) -> binary().
rand_bytes(N) when N > 0 ->
    try
        crypto:strong_rand_bytes(N)
    catch
        error:low_entropy ->
            list_to_binary([ rand_uniform(256) || _X <- lists:seq(1, N) ])
    end.

rand_uniform(N) ->
    rand:uniform(N) - 1.

%%
%% -----------------------------------------------------------------------------
%% Some unit tests
%% -----------------------------------------------------------------------------
%%

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

smoke_test() ->
  Term = {a, b, c, [d, "e", <<"foo">>]},
  Secret = <<"TopSecRet">>,
  Enc = encode(Term, Secret),
  ?assertEqual({ok, Term}, decode(Enc, Secret)),
  % forged data
  ?assertEqual({error, forged}, decode(<<"1">>, Secret)),
  ?assertEqual({error, forged}, decode(<<"0", Enc/binary>>, Secret)),
  ?assertEqual({error, invalid_token}, decode(<<Enc/binary, "1">>, Secret)).

expiry_test() ->
  Term = {a, b, c, [d, "e", <<"foo">>]},
  Secret = <<"TopSecRet">>,
  % check_expired returns error when term is not expiring
  ?assertEqual({error, badarg}, check_expired(Term)),
  % encode an expiring term
  Enc = encode(expiring(Term, 10), Secret),
  % decode it back
  {ok, Dec} = decode(Enc, Secret),
  % ensure term is not expired
  ?assertEqual({ok, Term}, check_expired(Dec)),
  % wait until it expires
  ?assertEqual({error, expired}, check_expired(Dec, timestamp(11))).

encode64_test() ->
  Term = {a, b, c, [d, "e", <<"foo">>]},
  Secret = <<"TopSecRet">>,
  ?assertEqual({error, forged}, decode_base64(undefined, a)),
  ?assertEqual({ok, Term}, decode_base64(encode_base64(Term, Secret), Secret)).

decode64_test() ->
  ?assertEqual({error, forged}, decode_base64(<<"%3A">>, a)).

token_test() ->
  Term = {a, b, c, [d, "e", <<"foo">>]},
  Secret = <<"TopSecRet">>,
  ?assertEqual({ok, Term},
      verify_token(issue_token(Term, Secret, 10), Secret)),
  ?assertEqual({error, invalid_token},
      verify_token(issue_token(Term, Secret, 10), << Secret/binary, "1" >>)),
  ?assertEqual({ok, Term},
      verify_token(encode_base64(Term, Secret), Secret)),
  ?assertEqual({ok, Term},
      verify_token(issue_token(Term, Secret), Secret)).

-endif.
