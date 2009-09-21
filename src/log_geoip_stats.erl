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

%% @doc A gen_log_analyzer behaviour module for counting the number of
%% web access log entries per country.
%%
%% For each parsed web log entry, the client's country is determined
%% from the GeoIP location of the client's IP address). The GeoIP
%% location is determined using the `libgeoip' Erlang library. The
%% `libgeoip' application must be started and configured before
%% starting parsing, like:
%% ```application:start(libgeoip_app).
%%    libgeoip:set_db(".../GeoIPCity.dat").'''

-module(log_geoip_stats).
-copyright("2009 Google Inc.").
-author("Romain Lenglet <romain.lenglet@berabera.info>").

-behaviour(gen_log_analyzer).

-export([start_link/0, get_stats/2]).

% Functions implementing the gen_log_analyzer behaviour:
-export([init/1, handle_log_entry/2, handle_call/3, handle_cast/2, terminate/2,
	 code_change/3]).

-include("WebAccessLog.hrl").

-record(state, {stats}).


start_link() ->
    gen_log_analyzer:start_link(?MODULE, [], []).

get_stats(Name, Length) ->
    Stats = dict:to_list(gen_log_analyzer:call(Name, get_stats)),
    Total = lists:foldl(fun({_, Count}, Total) -> Total + Count end,
			0, Stats),
    Stats1 = lists:sort(fun({_, C1}, {_, C2}) -> C1 > C2 end, Stats),
    Stats2 = lists:sublist(Stats1, Length),
    lists:map(fun({Country, Count}) -> {Country, Count*100/Total} end, Stats2).

init([]) ->
    State = #state{stats=dict:new()},
    {ok, State}.

handle_log_entry(LogEntry, State) ->
    case LogEntry#'LogEntry'.'remote-host' of
	{'ip-address', IPAddress} ->
	    case libgeoip:lookup(list_to_binary(IPAddress)) of
		{geoip, Country, _, _, _, _, _, _, _} ->
		    State1 = update_country(list_to_atom(Country), State),
		    {ok, State1};
		[] ->
		    % Unknown to the GeoIP library:
		    State1 = update_country('unknown', State),
		    {ok, State1}
	    end;
	_Else ->
	    % If the client address is a hostname or an ip6-address,
	    % count it as 'unknown':
	    State1 = update_country('unknown', State),
	    {ok, State1}
    end.

update_country(Country, State) ->
    Stats = State#state.stats,
    Stats1 = dict:update_counter(Country, 1, Stats),
    State#state{stats=Stats1}.

handle_call(get_stats, _, State) ->
    {reply, State#state.stats, State}.

handle_cast(_, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
