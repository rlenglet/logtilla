%% @copyright 2009 Google Inc.
%% @author Romain Lenglet <romain.lenglet@berabera.info>
%%   [http://www.berabera.info/]
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

%% @private

%% @doc A basic module for testing the basic mechanisms for
%% using the gen_log_analyzer behaviour.

-module(logtilla_test).
-copyright("2009 Google Inc.").
-author("Romain Lenglet <romain.lenglet@berabera.info>").

-behaviour(gen_log_analyzer).

-export([start_link/0, get_stats/1]).

% Functions implementing the gen_log_analyzer behaviour:
-export([init/1, handle_log_entry/2, handle_call/3, handle_cast/2, terminate/2,
	 code_change/3]).

-include("WebAccessLog.hrl").

-record(state, {count_without_length=0, count_with_length=0}).


start_link() ->
    gen_log_analyzer:start_link(?MODULE, [], []).

get_stats(Name) ->
    gen_log_analyzer:call(Name, get_stats).

init([]) ->
    State = #state{},
    {ok, State}.

handle_log_entry(LogEntry, State) ->
    % Example of filtering:
    case LogEntry#'LogEntry'.length of
	asn1_NOVALUE ->
	    {ok, State#state{
		   count_without_length=State#state.count_without_length+1}};
	_Length ->
	    {ok, State#state{
		   count_with_length=State#state.count_with_length+1}}
    end.

handle_call(get_stats, _, State) ->
    {reply, {State#state.count_without_length, State#state.count_with_length},
     State}.

handle_cast(_, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    io:format("without length=~w; with length=~w~n",
	      [State#state.count_without_length,
	       State#state.count_with_length]),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
