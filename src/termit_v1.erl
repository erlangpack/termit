
-module(termit_v1).

-export([
  decode/2
]).

%% All routines using outdated crypto algorithms like md5, sha, etc.

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

decode(<< Sig:20/binary, Enc/binary >>, Secret) ->
  Key = key(Secret),
  % NB constant time signature verification
  case equal(Sig, sign(Enc, Key)) of
    true ->
      % deserialize
      try binary_to_term(uncrypt(Enc, Key), [safe]) of
        Term -> {ok, Term}
      catch _:_ ->
        {error, badarg}
      end;
    false ->
      {error, forged}
  end;

%% N.B. unmatched binaries are forged
decode(Bin, _) when is_binary(Bin) ->
  {error, forged}.

%%
%% -----------------------------------------------------------------------------
%% @doc Serialize Term, encrypt and sign the result with Secret.
%% Return binary().
%% -----------------------------------------------------------------------------
%%

-spec key(
    Secret :: binary()) ->
  MAC16 :: binary().

key(Secret) ->
  crypto:mac(hmac, md5, Secret, []).

-spec sign(
    Data :: binary(),
    Secret :: binary()) ->
  MAC20 :: binary().

sign(Data, Key) ->
  crypto:mac(hmac, sha, Key, Data).

-spec uncrypt(
    Cipher :: binary(),
    Key :: binary()) ->
  Uncrypted :: binary().

uncrypt(<< IV:16/binary, Data/binary >>, Key) ->
  crypto:crypto_one_time(aes_128_cfb128, Key, IV, Data, false).

%%
%% -----------------------------------------------------------------------------
%% 'Constant' time =:= operator for binaries, to mitigate timing attacks
%% -----------------------------------------------------------------------------
%%

-spec equal(
    A :: binary(),
    B :: binary()) ->
  true |
  false.

equal(A, B) ->
  equal(A, B, 0).

equal(<< A, As/binary >>, << B, Bs/binary >>, Acc) ->
  equal(As, Bs, Acc bor (A bxor B));
equal(<<>>, <<>>, 0) ->
  true;
equal(_As, _Bs, _Acc) ->
  false.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").


% This was the v1 version of encoded tokens. No longer needed, but
% here for the record.

%encode(Term, Secret) ->
%  Key = key(Secret),
%  Enc = encrypt(term_to_binary(Term, [compressed, {minor_version, 1}]),
%                Key, termit:rand_bytes(16)),
%  << (sign(Enc, Key))/binary, Enc/binary >>.

encrypt(Data, Key, IV) ->
  Crypt = crypto:crypto_one_time(aes_128_cfb128, Key, IV, Data, true),
  << IV/binary, Crypt/binary>>.


encrypt_test() ->
  IV = crypto:strong_rand_bytes(16),
  Secret = crypto:mac(hmac, md5, <<"Make It Elegant">>, []),
  << Secret15:15/binary, _/binary >> = Secret,
  Bin = <<"Transire Benefaciendo">>,
  ?assertEqual(Bin, uncrypt(encrypt(Bin, Secret, IV), Secret)),
  ?assertNotEqual(Bin,
      uncrypt(encrypt(Bin, Secret, IV), <<Secret15/binary, "1">>)),
  ?assertNotEqual(Bin,
      uncrypt(encrypt(Bin, Secret, IV), <<"0", Secret15/binary>>)),
  ?assertNotEqual(Bin,
      uncrypt(encrypt(Bin, <<Secret15/binary, "1">>, IV), Secret)),
  ?assertNotEqual(Bin,
      uncrypt(encrypt(Bin, <<"0", Secret15/binary>>, IV), Secret)).


-endif.
