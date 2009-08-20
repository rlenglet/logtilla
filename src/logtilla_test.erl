%% @copyright 2009 Google Inc.
%% @author Romain Lenglet <romain.lenglet@laposte.net>
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

%% A basic module for testing the basic mechanisms for interacting
%% with the logtilla_parser port program.

%% TODO(Romain): Extend and refactor this module to define an Erlang
%% behaviour for log entry analysis, and for using operations ala
%% ROSE/CIMP, using linked replies, etc. to interact with the port
%% program.

-module(logtilla_test).
-export([start/1]).
-export([init/2]).

-include("CommonLog.hrl").

start(Name) ->
    case whereis(Name) of
	undefined ->
	    Self = self(),
	    Pid = spawn_link(fun() -> init(Self, Name) end),
	    receive
		started -> Pid;
		quit -> ok
	    end;
	_ -> {already_started, Name}
    end.
			  
init(Client, Name) ->
    process_flag(trap_exit, true),
    register(Name, self()),
    Client ! started,
    Port = start_logtilla_parser(),
    read_log(Port).

start_logtilla_parser() ->
    open_port({spawn, "logtilla-parser"},
	      [{packet, 2}, binary, exit_status]).

read_log(Port) ->
    receive
	{Port, {data, Data}} ->
	    handle_log_entry(Data),
	    read_log(Port);
	{'EXIT', Port, Reason} ->
	    process_flag(trap_exit, false),
	    exit({port_died, Reason})
    end.

handle_log_entry(Data) ->  %% TODO(Romain): Make generic behaviour callbacks.
    {ok, LogEntry} = 'CommonLog':decode('LogEntry', Data),
    %% Example of filtering / Map:
    Time = LogEntry#'LogEntry'.time,
    case LogEntry#'LogEntry'.length of
	asn1_NOVALUE -> io:format("~s: no length~n", [Time]);
	Length -> io:format("~s: ~w~n", [Time, Length])
    end.
