# SMTP/IMAP/POP3 DPD payload signatures. Identification must not depend on ports.
# Signature IDs are SecureMail-prefixed so they do not collide with Zeek built-ins.

signature sm_dpd_smtp_client {
	ip-proto == tcp
	payload /(|.*[\n\r])[[:space:]]*([hH][eE][lL][oO]|[eE][hH][lL][oO])/
	requires-reverse-signature sm_dpd_smtp_server
	enable "smtp"
	tcp-state originator
}

signature sm_dpd_smtp_server {
	ip-proto == tcp
	payload /^[[:space:]]*220[[:space:]-]/
	tcp-state responder
}

signature sm_dpd_imap_server {
	ip-proto == tcp
	payload /^\* OK/
	requires-reverse-signature sm_dpd_imap_client
	enable "imap"
	tcp-state responder
}

signature sm_dpd_imap_client {
	ip-proto == tcp
	payload /(|.*[\r\n])[a-zA-Z0-9._-]+[ \t]+([cC][aA][pP][aA][bB][iI][lL][iI][tT][yY]|[sS][tT][aA][rR][tT][tT][lL][sS]|[lL][oO][gG][oO][uU][tT]|[nN][oO][oO][pP])/
	tcp-state originator
}

signature sm_dpd_pop3_server {
	ip-proto == tcp
	payload /^\+OK/
	requires-reverse-signature sm_dpd_pop3_client
	enable "pop3"
	tcp-state responder
}

signature sm_dpd_pop3_client {
	ip-proto == tcp
	payload /(|.*[\r\n])[[:space:]]*([uU][sS][eE][rR][[:space:]]|[cC][aA][pP][aA]|[sS][tT][lL][sS]|[qQ][uU][iI][tT]|[sS][tT][aA][tT]|[aA][uU][tT][hH])/
	tcp-state originator
}

# Greeting-like responder line used only to flag unclassified banners.
# Does not enable an analyzer. The matching payload is never logged.
signature sm_greeting_line {
	ip-proto == tcp
	payload /^[\x20-\x7e]{3,80}\x0d\x0a/
	tcp-state responder
	event "sm_ambiguous_greeting"
}
