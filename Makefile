ERL ?= erl
REBAR := ./rebar3
REBAR_URL := https://s3.amazonaws.com/rebar3/rebar3

.PHONY: all compile check test clean

all: ./rebar3 compile check test

$(REBAR):
	$(ERL) -noshell -s inets -s ssl \
	  -eval '{ok, saved_to_file} = httpc:request(get, {"$(REBAR_URL)", []}, [{ssl, [ {verify, verify_none} ]}], [{stream, "$(REBAR)"}])' \
	  -s init stop
	chmod +x $(REBAR)

compile:
	$(REBAR) compile

clean:
	$(REBAR) clean

check:
	$(REBAR) eunit

test: compile check
	$(REBAR) ct

dialyzer:
	$(REBAR) dialyzer

xref:
	$(REBAR) xref
