# Extract TLS certificate DER via Zeek file analysis. x509.log is a cross-check
# only; Python parses the extracted bytes. Payload contents are never logged.

@load base/files/hash
@load base/files/extract
@load base/files/x509

module SM_CERT;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts: time &log;
		uid: string &log &optional;
		fuid: string &log;
		sha256: string &log &optional;
		sha1: string &log &optional;
		mime_type: string &log &optional;
		seen_bytes: count &log &optional;
		extracted: string &log &optional;
		truncated: bool &log &default=F;
	};
}

redef FileExtract::prefix = "certs/";
redef FileExtract::default_limit = 65536;

const cert_mime_types: set[string] = {
	"application/pkix-cert",
	"application/x-x509-user-cert",
	"application/x-x509-ca-cert",
	"application/x-x509-ca-ra-cert",
};

event zeek_init() &priority=5
	{
	Log::create_stream(SM_CERT::LOG, [$columns=Info, $path="sm_cert"]);
	}

function is_ssl_cert(f: fa_file, mime_type: string): bool
	{
	if ( f$source != "SSL" )
		return F;
	if ( mime_type in cert_mime_types )
		return T;
	# Malformed Certificate messages may lack a recognised MIME type.
	return mime_type == "" || mime_type == "application/octet-stream";
	}

event file_sniff(f: fa_file, meta: fa_metadata)
	{
	local mime = meta?$mime_type ? meta$mime_type : "";
	if ( ! is_ssl_cert(f, mime) )
		return;
	Files::add_analyzer(f, Files::ANALYZER_SHA1);
	Files::add_analyzer(f, Files::ANALYZER_SHA256);
	Files::add_analyzer(f, Files::ANALYZER_EXTRACT,
	    [$extract_filename=fmt("%s.der", f$id)]);
	}

event file_state_remove(f: fa_file)
	{
	if ( f$source != "SSL" )
		return;
	local rec: Info = [$ts=network_time(), $fuid=f$id];
	if ( f?$conns )
		{
		for ( cid in f$conns )
			{
			rec$uid = f$conns[cid]$uid;
			break;
			}
		}
	if ( f?$info )
		{
		if ( f$info?$sha256 )
			rec$sha256 = f$info$sha256;
		if ( f$info?$sha1 )
			rec$sha1 = f$info$sha1;
		if ( f$info?$mime_type )
			rec$mime_type = f$info$mime_type;
		if ( f$info?$seen_bytes )
			rec$seen_bytes = f$info$seen_bytes;
		if ( f$info?$extracted )
			rec$extracted = f$info$extracted;
		if ( f$info?$extracted_cutoff )
			rec$truncated = f$info$extracted_cutoff;
		}
	Log::write(SM_CERT::LOG, rec);
	}
