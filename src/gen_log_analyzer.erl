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

%% @doc A generic behaviour for analyzing entries of web access log
%% files. This behaviour is internally implemented as a gen_server.
%%
%% The following callback function must be implemented in any module
%% implementing this behaviour:
%%
%% <ul>
%% <li>
%% `init/1': Initialize the state.
%% ```init(Args::any()) ->
%%        {'ok', State::any()}
%%        | 'ignore'
%%        | {'stop', Reason::any()}.'''
%% </li>
%% <li>
%% `handle_log_entry/2': Handle a parsed log entry.
%% The {@type LogEntry} record type is defined in header file
%% `WebAccessLog.hrl'.
%% ```handle_log_entry(LogEntry::#'LogEntry'(), State::any()) ->
%%        {'ok', NewState::any()}
%%        | {'error', Reason::any(), NewState::any()}.'''
%% </li>
%% <li>
%% `handle_call/3': Handle an application-specific call.
%% This callback is similar to the {@link gen_server:handle_call/3}
%% callback.
%% ```handle_call(Msg::any(), {From::pid(), Tag::any()},
%%                State::any()) ->
%%        {'reply', Reply::any(), NewState::any()}
%%        | {'reply', Reply::any(), NewState::any(), Timeout::timeout()}
%%        | {'noreply', NewState::any()}
%%        | {'noreply', NewState::any(), Timeout::timeout()}
%%        | {'stop', Reason::any(), Reply::any(), NewState::any()}.'''
%% </li>
%% <li>
%% `handle_cast/2': Handle an application_specific cast.
%% This callback is similar to the {@link gen_server:handle_cast/2}
%% callback.
%% ```handle_cast(Msg::any(), State::any()) ->
%%        {'noreply', NewState::any()}
%%        | {'noreply', NewState::any(), Timeout::timeout()}
%%        | {'stop', Reason::any(), NewState::any()}.'''
%% </li>
%% <li>
%% `terminate/2': Cleanup on termination.
%% This callback is similar to the {@link gen_server:terminate/2}
%% callback.
%% ```terminate(Reason::any(), State::any()) ->
%%        no_return().'''
%% </li>
%% <li>
%% `code_change/3': Update the state after a module upgrade.
%% This callback is similar to the {@link gen_server:code_change/3}
%% callback.
%% ```code_change({'down', OldVsn::any()} | OldVsn::any(), State::any(),
%%                Extra::any()) ->
%%        {'ok', NewState::any()}.'''
%% </li>
%% </ul>
%%
%% Here is an example of usage of this module, with a behaviour module
%% called `logtilla_test':
%% ```{ok, Pid} = gen_log_analyzer:start_link(logtilla_test, [], []),
%%    ok = gen_log_analyzer:parse(Pid, "access.log"),
%%    ok = gen_log_analyzer:parse(Pid, "access.log.1"),
%%    gen_log_analyzer:stop(Pid).'''

-module(gen_log_analyzer).
-behaviour(gen_server).

-export([start/3, start/4, start_link/3, start_link/4,
	 parse/2, call/2, cast/2, stop/1]).

%% Internal exports of the gen_server callbacks:
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
	 code_change/3]).

%% State maintained for each pending ParseLogFile operation:
-record(op_state, {filename::string(), pid::pid(), tag::any()}).

%% State of a log analyzer:
-record(state, {mod::atom(), state::any(), port::port(),
		op_ids::gb_set(), op_states::dict()}).


%% Behaviour definition export:
-export([behaviour_info/1]).

-include("WebAccessLogParserOperations.hrl").


%% =============================================================================
%% == Behaviour definitions ==
%% =============================================================================

%% @doc Define the callbacks that must be implemented in modules
%% implementing the gen_log_analyzer behaviour.
%%
%% @spec behaviour_info(Option::atom()) ->
%%     'undefined' | [{Name::atom(), Arity::integer()}]

-spec behaviour_info(atom()) -> 'undefined' | [{atom(), arity()}].

behaviour_info(callbacks) ->
    [{init, 1}, {handle_log_entry, 2}, {handle_call, 3}, {handle_cast, 2},
     {terminate, 2}, {code_change, 3}];
behaviour_info(_Other) ->
    undefined.


%% =============================================================================
%% == Public API ==
%% =============================================================================

%% @type start_name() = {'local', atom()} | {'global', atom()}
%%
%% @type flag() = 'trace' | 'log' | {'logfile', string()}
%%     | 'statistics' | 'debug'
%%
%% @type timeout() = 'infinity' | integer()
%%
%% @type start_opts() = [{'timeout', timeout()} | {'debug', [flag()]}]
%%
%% @type start_ret() = {'ok', pid()} | {'error', {'already_started', pid()}}
%%     | {'error', term()}

-type start_name() :: {'local', atom()} | {'global', atom()}.
-type flag() :: 'trace' | 'log' | {'logfile', string()}
    | 'statistics' | 'debug'.
-type start_opts() :: [{'timeout', timeout()} | {'debug', [flag()]}].
-type start_ret() :: {'ok', pid()} | {'error', {'already_started', pid()}}
    | {'error', term()}.

%% @doc Starts a parser process with no name. The `Mod:init(Args)'
%% callback is called on the given behaviour module to initialize the
%% state.
%%
%% @spec start(Mod::atom(), Args::any(), Options::start_opts()) ->
%%     start_ret()

-spec start(atom(), any(), start_opts()) -> start_ret().

start(Mod, Args, Options) ->
    gen_server:start(?MODULE, [Mod, Args], Options).

%% @doc Starts a parser process and registers it with the given name.
%% The `Mod:init(Args)' callback is called on the given behaviour
%% module to initialize the state.
%%
%% @spec start(Name::start_name(), Mod::atom(), Args::any(),
%%             Options::start_opts()) ->
%%     start_ret()

-spec start(start_name(), atom(), any(), start_opts()) -> start_ret().

start(Name, Mod, Args, Options) ->
    gen_server:start(Name, ?MODULE, [Mod, Args], Options).

%% @doc Starts a parser process with no name, and links it to this
%% process. The `Mod:init(Args)' callback is called on the given
%% behaviour module to initialize the state.
%%
%% @spec start_link(Mod::atom(), Args::any(), Options::start_opts()) ->
%%     start_ret()

-spec start_link(atom(), any(), start_opts()) -> start_ret().

start_link(Mod, Args, Options) ->
    gen_server:start_link(?MODULE, [Mod, Args], Options).

%% @doc Starts a parser process, registers it with the given name, and
%% links it to this process. The `Mod:init(Args)' callback is called
%% on the given behaviour module to initialize the state.
%%
%% @spec start_link(Name::start_name(), Mod::atom(), Args::any(),
%%                  Options::start_opts()) ->
%%     start_ret()

-spec start_link(start_name(), atom(), any(), start_opts()) -> start_ret().

start_link(Name, Mod, Args, Options) ->
    gen_server:start_link(Name, ?MODULE, [Mod, Args], Options).

-type name() :: pid() | atom() | {'global', atom()} | {'local', atom()}
| {atom(), atom()}.

%% @doc Start parsing the log file with the given filename.  The
%% `Mod:handle_log_entry(LogEntry, State)' callback is called on the
%% behaviour module for each successfully parsed entry. The call
%% blocks until the file is completely parsed, or an error occurs.
%%
%% @spec parse(Name::name(), FileName::string()) -> 'ok' | {'error', any()}

-spec parse(name(), string()) -> 'ok' | {'error', any()}.

parse(Name, FileName) ->
    gen_server:call(Name, {parse, FileName}).

%% @doc Make an application-specific call. The `Mod:handle_call(Msg,
%% _, State)' callback is called on the behaviour module.
%%
%% @spec call(Name::name(), Msg::any()) -> any()

-spec call(name(), any()) -> any().

call(Name, Msg) ->
    gen_server:call(Name, {call, Msg}).

%% @doc Make an application-specific cast. The `Mod:handle_cast(Msg,
%% State)' callback is called on the behaviour module.
%%
%% @spec cast(Name::name(), Msg::any()) -> any()

-spec cast(name(), any()) -> 'ok'.

cast(Name, Msg) ->
    gen_server:cast(Name, {cast, Msg}).

%% @doc Stop the parser process.
%%
%% @spec stop(Name::name()) -> 'ok'

-spec stop(name()) -> 'ok'.

stop(Name) ->
    gen_server:cast(Name, stop).

%% =============================================================================
%% == Internal implementation ==
%% =============================================================================

%% -----------------------------------------------------------------------------
%% === gen_server callbacks ===
%% -----------------------------------------------------------------------------

%% @doc Initialize the parser. Start the parser as a port program, and
%% call the `Mod:init(Args)' callback on the behaviour module.
%%
%% @spec init([atom() | any()]) ->
%%     {'ok', State::#state{}} | 'ignore' | {'stop', Reason::any()}

-spec init(ModAndArgs::[atom() | any()]) ->
    {'ok', #state{}} | 'ignore' | {'stop', any()}.

init([Mod, Args]) ->
    % TODO(Romain): support additional options to specify the
    % executable's path, etc.
    Port = open_port({spawn, "logtilla-parser"},
		     [{packet, 2}, binary, eof, exit_status]),
    case catch Mod:init(Args) of
	{ok, State} ->
	    {ok, #state{mod=Mod, state=State, port=Port,
			op_ids=gb_sets:new(), op_states=dict:new()}};
	ignore -> ignore;
	{stop, Reason} -> {stop, Reason}
    end.

%% @doc Handle a call, to either parse a log file or forward a call to
%% the behaviour module. This callback is executed when calling {@link
%% parse/2} or {@link call/2}.
%%
%% @spec handle_call(Msg::{'parse', FileName::string()}
%%                   | {'call', Msg1::any()},
%%                   Caller::{From::pid(), Tag::any()}, State::#state{}) ->
%%     {'reply', Reply::any(), NewState::#state{}}
%%     | {'reply', Reply::any(), NewState::#state{}, Timeout::timeout()}
%%     | {'noreply', NewState::#state{}}
%%     | {'noreply', NewState::#state{}, Timeout::timeout()}
%%     | {'stop', Reason::any(), Reply::any(), NewState::#state{}}

-spec handle_call({'parse', string()} | {'call', any()}, {pid(), any()},
		  #state{}) ->
    {'reply', any(), #state{}}
    | {'reply', any(), #state{}, timeout()}
    | {'noreply', #state{}}
    | {'noreply', #state{}, timeout()}
    | {'stop', any(), any(), #state{}}.

handle_call({parse, FileName}, {From, Tag}, State) ->
    Port = State#state.port,
    OpState = #op_state{filename=FileName, pid=From, tag=Tag},
    {InvokeId, State1} = add_operation(OpState, State),
    Invoke = #'ParseLogFile'{'invoke-id'=InvokeId,
			     'argument'=FileName},
    {ok, PDU} = 'WebAccessLogParserOperations':encode(
		  'ConsumerPDU', {'parse-log-file', Invoke}),
    % Using the {packet, 2} option for the port, the PDU will be
    % prefixed by its size as a 16-bit integer:
    port_command(Port, PDU),
    % Reply to the call only after we receive an error during parsing,
    % or after finishing parsing the file:
    {noreply, State1};

handle_call({call, Msg}, {From, Tag}, State) ->
    Mod = State#state.mod,
    State1 = State#state.state,
    case Mod:handle_call(Msg, {From, Tag}, State1) of
	{reply, Reply, State2} ->
	    {reply, Reply, State#state{state=State2}};
	{reply, Reply, State2, Timeout} ->
	    {reply, Reply, State#state{state=State2}, Timeout};
	{noreply, State2} ->
	    {noreply, State#state{state=State2}};
	{noreply, State2, Timeout} ->
	    {noreply, State#state{state=State2}, Timeout};
	{stop, Reason, Reply, State2} ->
	    {stop, Reason, Reply, State#state{state=State2}}
    end.

%% @doc Handle a cast, to either stop this process or forward a cast
%% to the behaviour module. This callback is executed when calling
%% {@link stop/1} or {@link cast/2}.
%%
%% @spec handle_cast(Msg::'stop' | {'cast', Msg1::any()}, State::#state{}) ->
%%     {'noreply', NewState::#state{}}
%%     | {'noreply', NewState::#state{}, Timeout::timeout()}
%%     | {'stop', Reson::any(), NewState::#state{}}

-spec handle_cast('stop' | {'cast', any()}, #state{}) ->
    {'noreply', #state{}}
    | {'noreply', #state{}, timeout()}
    | {'stop', any(), #state{}}.

handle_cast(stop, State) ->
    Port = State#state.port,
    port_close(Port),
    {stop, normal, State};

handle_cast({cast, Msg}, State) ->
    Mod = State#state.mod,
    State1 = State#state.state,
    case Mod:handle_cast(Msg, State1) of
	{noreply, State2} ->
	    {noreply, State#state{state=State2}};
	{noreply, State2, Timeout} ->
	    {noreply, State#state{state=State2}, Timeout};
	{stop, Reason, State2} ->
	    {stop, Reason, State#state{state=State2}}
    end.

%% @doc Handle messages received from the port program.
%%
%% @spec handle_info(Msg::{Port::port(), Msg1::binary()}, State::#state{}) ->
%%     {'noreply', NewState::#state{}}
%%     | {'noreply', NewState::#state{}, Timeout::timeout()}
%%     | {'stop', Reson::any(), NewState::#state{}}

-spec handle_info({port(), binary()}, #state{}) ->
    {'noreply', #state{}}
    | {'noreply', #state{}, timeout()}
    | {'stop', any(), #state{}}.

handle_info({Port, Msg}, State) when is_port(Port), Port =:= State#state.port ->
    handle_port_msg(Msg, State).

%% @doc Cleanup this behaviour's state.
%%
%% @spec terminate(Reason::any(), State::#state{}) -> no_return()

-spec terminate(any(), #state{}) ->
    no_return().

terminate(Reason, State) ->
    Port = State#state.port,
    port_close(Port),
    Mod = State#state.mod,
    State1 = State#state.state,
    Mod:terminate(Reason, State1).

%% @doc Update this module, and the behaviour module.
%%
%% @spec code_change(OldVsn::{'down', any()} | any(), State::#state{},
%%                   Extra::any()) ->
%%     {'ok', NewState::#state{}}

-spec code_change({'down', any()} | any(), #state{}, any()) ->
    {'ok', #state{}}.

code_change(OldVsn, State, Extra) ->
    Mod = State#state.mod,
    State1 = State#state.state,
    Mod:code_change(OldVsn, State1, Extra).


%% -----------------------------------------------------------------------------
%% === Internal implementation ===
%% -----------------------------------------------------------------------------

%% @doc Handle a message coming from the parser port program.

-spec handle_port_msg({'data', binary()} | 'eof' | {'exit_status', any()},
		      #state{}) ->
    {'reply', any(), #state{}}
    | {'reply', any(), #state{}, timeout()}
    | {'noreply', #state{}}
    | {'noreply', #state{}, timeout()}
    | {'stop', any(), any(), #state{}}.

handle_port_msg(Msg, State) ->
    case Msg of
	{data, Data} ->
	    handle_port_data(Data, State);
	eof ->
	    % TODO(Romain): log this unexpected termination
	    {noreply, State};
	{exit_status, ExitStatus} ->
	    {stop, {port_exit_status, ExitStatus}, State}
    end.

%% @doc Handle a binary PDU coming from the parser port
%% program. Decode the binary message as an ASN.1 SupplierPDU encoded
%% using BER, and pass it to {@link handle_port_data/2}.

-spec handle_port_data(binary(), #state{}) ->
    {'reply', any(), #state{}}
    | {'reply', any(), #state{}, timeout()}
    | {'noreply', #state{}}
    | {'noreply', #state{}, timeout()}
    | {'stop', any(), any(), #state{}}.
    
handle_port_data(Data, State) ->
    case 'WebAccessLogParserOperations':decode('SupplierPDU', Data) of
	{ok, PDU} -> handle_supplier_pdu(PDU, State);
	{error, Reason} -> {stop, {invalid_port_data, Reason}, State}
    end.

%% @doc Handle a decoded PDU coming from the parser port program.

-spec handle_supplier_pdu(tuple(), #state{}) ->
    {'reply', any(), #state{}}
    | {'reply', any(), #state{}, timeout()}
    | {'noreply', #state{}}
    | {'noreply', #state{}, timeout()}
    | {'stop', any(), any(), #state{}}.

handle_supplier_pdu(PDU, State) ->
    case PDU of
	{'cannot-open-file', CannotOpenFile} ->
	    #'CannotOpenFile'{'invoke-id'=InvokeId} = CannotOpenFile,
	    case get_operation(InvokeId, State) of
		{ok, #op_state{pid=Pid, tag=Tag}} ->
		    % Terminate the gen_server call with {'error', ...}:
		    gen_server:reply({Pid, Tag}, {error, cannot_open_file}),
		    State1 = del_operation(InvokeId, State),
		    {noreply, State1};
		error -> {stop, invalid_invoke_id, State}
	    end;

	{'return-log-entry', ReturnLogEntry} ->
	    #'ReturnLogEntry'{'linked-id'=LinkedId,
			      'argument'=LogEntry} = ReturnLogEntry,
	    case get_operation(LinkedId, State) of
		{ok, _OpState} ->
		    Mod = State#state.mod,
		    State1 = State#state.state,
		    case Mod:handle_log_entry(LogEntry, State1) of
			{ok, State2} ->
			    {noreply, State#state{state=State2}};
			{stop, Reason, State2} ->
			    {stop, Reason, State#state{state=State2}}
		    end;
		error -> {stop, invalid_linked_id, State}
	    end;

	{'end-of-file', EndOfFile} ->
	    #'EndOfFile'{'invoke-id'=InvokeId} = EndOfFile,
	    case get_operation(InvokeId, State) of
		{ok, #op_state{pid=Pid, tag=Tag}} ->
		    % Terminate the gen_server call with 'ok':
		    gen_server:reply({Pid, Tag}, ok),
		    State1 = del_operation(InvokeId, State),
		    {noreply, State1};
		error -> {stop, invalid_invoke_id, State}
	    end
    end.

%% @doc Modify this process' state to store the given state for a new
%% operation, and return an unambiguous invoke-id for that operation.

-spec add_operation(#op_state{}, #state{}) ->
    {integer(), #state{}}.

add_operation(OpState, State) ->
    {InvokeId, OperationIds} = gen_id(State#state.op_ids),
    OperationStates = dict:store(InvokeId, OpState,
				 State#state.op_states),
    State1 = State#state{op_ids=OperationIds,
			 op_states=OperationStates},
    {InvokeId, State1}.

%% @doc Get the state associated with an operation, given its
%% invoke-id.

-spec get_operation(integer(), #state{}) ->
    {'ok', #op_state{}} | 'error'.

get_operation(InvokeId, State) ->
    dict:find(InvokeId, State#state.op_states).

%% @doc Remove an operation's state from this process' state,
%% indicating that it has terminated.

-spec del_operation(integer(), #state{}) ->
    #state{}.

del_operation(InvokeId, State) ->
    OperationIds = del_id(InvokeId, State#state.op_ids),
    OperationStates = dict:erase(InvokeId, State#state.op_states),
    State#state{op_ids=OperationIds, op_states=OperationStates}.

%% @doc Get an identifier that is not in the given gb_set, and add it
%% to the set.

-spec gen_id(gb_set()) ->
    {integer(), gb_set()}.

gen_id(Set) ->
    NextId = case gb_sets:is_empty(Set) of
		 true -> 0;
		 false -> 1 + gb_sets:largest(Set)
	     end,
    {NextId, gb_sets:insert(NextId, Set)}.

%% @doc Remove an identifier from the given gb_set.

-spec del_id(integer(), gb_set()) ->
    gb_set().

del_id(Id, Set) ->
    gb_sets:del_element(Id, Set).
