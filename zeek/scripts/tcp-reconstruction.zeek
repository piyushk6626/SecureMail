# Metadata-only TCP reconstruction facts. Payload bytes are never logged.

@load base/protocols/conn
@load misc/capture-loss

module SM_TCP_RECON;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts: time &log;
		uid: string &log;
		id: conn_id &log;
		is_orig: bool &log &optional;
		event_type: string &log;
		seq: count &log &optional;
		len: count &log &optional;
		range_start: count &log &optional;
		range_end: count &log &optional;
	};
}

redef tcp_max_old_segments = 8;

global next_seq: table[string, bool] of count;
global high_water: table[string, bool] of count;
global saw_future: table[string, bool] of bool;

function write_evt(c: connection, is_orig: bool, etype: string, seq: count, len: count)
	{
	local rec: Info = [$ts=network_time(), $uid=c$uid, $id=c$id, $event_type=etype];
	rec$is_orig = is_orig;
	if ( seq > 0 )
		rec$seq = seq;
	if ( len > 0 )
		rec$len = len;
	if ( seq > 0 && len > 0 )
		{
		rec$range_start = seq;
		rec$range_end = seq + len;
		}
	Log::write(LOG, rec);
	}

event zeek_init()
	{
	Log::create_stream(SM_TCP_RECON::LOG, [$columns=Info, $path="sm_tcp_recon"]);
	}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
	{
	# `payload` is intentionally unused: never log application bytes.
	if ( "S" in flags )
		{
		next_seq[c$uid, is_orig] = 1;
		return;
		}
	if ( len == 0 )
		return;
	if ( [c$uid, is_orig] !in next_seq )
		{
		next_seq[c$uid, is_orig] = seq + len;
		return;
		}

	local expected = next_seq[c$uid, is_orig];
	if ( seq == expected )
		{
		if ( [c$uid, is_orig] in saw_future && saw_future[c$uid, is_orig] )
			write_evt(c, is_orig, "out_of_order", seq, len);
		local nxt = seq + len;
		if ( [c$uid, is_orig] in high_water && high_water[c$uid, is_orig] > nxt )
			nxt = high_water[c$uid, is_orig];
		next_seq[c$uid, is_orig] = nxt;
		}
	else if ( seq > expected )
		{
		saw_future[c$uid, is_orig] = T;
		local hw = seq + len;
		if ( [c$uid, is_orig] !in high_water || high_water[c$uid, is_orig] < hw )
			high_water[c$uid, is_orig] = hw;
		}
	else if ( seq + len <= expected )
		write_evt(c, is_orig, "duplicate", seq, len);
	else
		write_evt(c, is_orig, "overlap", seq, expected - seq);
	}

event content_gap(c: connection, is_orig: bool, seq: count, length: count)
	{
	write_evt(c, is_orig, "seq_gap", seq, length);
	}

event tcp_rexmit(c: connection, is_orig: bool, seq: count, len: count, data_in_flight: count, window: count)
	{
	write_evt(c, is_orig, "rexmit", seq, len);
	}

event rexmit_inconsistency(c: connection, t1: string, t2: string, tcp_flags: string)
	{
	# Log only the overlapping length, never t1/t2 contents.
	local overlap: count = |t1|;
	if ( |t2| < overlap )
		overlap = |t2|;
	local rec: Info = [$ts=network_time(), $uid=c$uid, $id=c$id, $event_type="rexmit_inconsistency"];
	rec$len = overlap;
	Log::write(LOG, rec);
	}
