# Unified sm_email.log: protocol identity plus bounded, redacted command/response lines.
# Packet payloads, credentials, and message bodies are never written.

@load base/frameworks/analyzer

module SM_EMAIL;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts: time &log;
		uid: string &log;
		id: conn_id &log;
		protocol: string &log;
		is_orig: bool &log &optional;
		event_type: string &log;
		command: string &log &optional;
		argument: string &log &optional;
		reply_code: count &log &optional;
		text: string &log &optional;
	};
}

const max_text_len: count = 128;
const secret_commands: set[string] = {
	"AUTH",
	"LOGIN",
	"USER",
	"PASS",
	"APOP",
	"AUTHENTICATE",
	"AUTH_ANSWER",
	"**",
	"MAIL",
	"RCPT",
};

const pop3_ports: set[port] = { 110/tcp };

global confirmed_uids: set[string];
global greeting_uids: set[string];
global pop3_capa_uids: set[string];

function bound_text(s: string): string
	{
	if ( |s| <= max_text_len )
		return s;
	return s[0:max_text_len];
	}

function redact_argument(command: string, arg: string): string
	{
	if ( to_upper(command) in secret_commands )
		return "<redacted>";
	return bound_text(arg);
	}

function write_row(c: connection, protocol: string, is_orig: bool, etype: string): Info
	{
	local rec: Info = [$ts=network_time(), $uid=c$uid, $id=c$id, $protocol=protocol,
	    $event_type=etype];
	rec$is_orig = is_orig;
	return rec;
	}

function mark_confirmed(uid: string)
	{
	add confirmed_uids[uid];
	}

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_POP3, pop3_ports);
	Log::create_stream(SM_EMAIL::LOG, [$columns=Info, $path="sm_email"]);
	}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
	{
	local rec = write_row(c, "smtp", is_orig, "request");
	rec$command = bound_text(to_upper(command));
	if ( |arg| > 0 )
		rec$argument = redact_argument(command, arg);
	Log::write(LOG, rec);
	mark_confirmed(c$uid);
	}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool)
	{
	local rec = write_row(c, "smtp", is_orig, "reply");
	if ( |cmd| > 0 )
		rec$command = bound_text(to_upper(cmd));
	rec$reply_code = code;
	if ( rec?$command && rec$command in secret_commands )
		rec$text = "<redacted>";
	else if ( |msg| > 0 )
		rec$text = bound_text(msg);
	Log::write(LOG, rec);
	mark_confirmed(c$uid);
	}

event smtp_starttls(c: connection)
	{
	Log::write(LOG, write_row(c, "smtp", T, "starttls"));
	mark_confirmed(c$uid);
	}

event imap_capabilities(c: connection, capabilities: string_vec)
	{
	local rec = write_row(c, "imap", F, "capability");
	rec$text = bound_text(join_string_vec(capabilities, " "));
	Log::write(LOG, rec);
	mark_confirmed(c$uid);
	}

event imap_starttls(c: connection)
	{
	Log::write(LOG, write_row(c, "imap", T, "starttls"));
	mark_confirmed(c$uid);
	}

event pop3_request(c: connection, is_orig: bool, command: string, arg: string)
	{
	local rec = write_row(c, "pop3", is_orig, "request");
	rec$command = bound_text(to_upper(command));
	if ( |arg| > 0 )
		rec$argument = redact_argument(command, arg);
	Log::write(LOG, rec);
	mark_confirmed(c$uid);
	if ( rec$command == "CAPA" )
		add pop3_capa_uids[c$uid];
	else
		delete pop3_capa_uids[c$uid];
	}

event pop3_reply(c: connection, is_orig: bool, cmd: string, msg: string)
	{
	local rec = write_row(c, "pop3", is_orig, "reply");
	if ( |cmd| > 0 )
		rec$text = bound_text(to_upper(cmd));
	if ( |msg| > 0 )
		{
		if ( rec?$text )
			rec$text = bound_text(fmt("%s %s", rec$text, msg));
		else
			rec$text = bound_text(msg);
		}
	Log::write(LOG, rec);
	mark_confirmed(c$uid);
	}

event pop3_starttls(c: connection)
	{
	Log::write(LOG, write_row(c, "pop3", T, "starttls"));
	mark_confirmed(c$uid);
	}

event pop3_data(c: connection, is_orig: bool, data: string)
	{
	if ( c$uid !in pop3_capa_uids )
		return;
	if ( data == "." )
		{
		delete pop3_capa_uids[c$uid];
		return;
		}
	if ( |data| == 0 )
		return;
	local rec = write_row(c, "pop3", is_orig, "capability");
	rec$text = bound_text(data);
	Log::write(LOG, rec);
	mark_confirmed(c$uid);
	}

event pop3_unexpected(c: connection, is_orig: bool, msg: string, detail: string)
	{
	# `detail` is intentionally unused: it can contain credentials or raw lines.
	local rec = write_row(c, "pop3", is_orig, "unexpected");
	if ( |msg| > 0 )
		rec$text = bound_text(msg);
	Log::write(LOG, rec);
	mark_confirmed(c$uid);
	}

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo)
	{
	if ( ! info?$c )
		return;
	if ( atype == Analyzer::ANALYZER_IMAP )
		{
		Log::write(LOG, write_row(info$c, "imap", F, "confirmation"));
		mark_confirmed(info$c$uid);
		}
	}

event signature_match(state: signature_state, msg: string, data: string)
	{
	# `data` is intentionally unused: never log matching payload bytes.
	if ( msg == "sm_ambiguous_greeting" )
		add greeting_uids[state$conn$uid];
	}

event connection_state_remove(c: connection)
	{
	if ( c$uid in confirmed_uids )
		return;
	if ( c$uid in greeting_uids )
		Log::write(LOG, write_row(c, "unknown", F, "ambiguous_banner"));
	}
