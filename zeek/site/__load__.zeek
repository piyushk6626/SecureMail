redef global_hash_seed = "securemail-v0";

@load base/protocols/conn
@load policy/protocols/ssl/ssl-log-ext
@load policy/protocols/ssl/validate-certs
@load base/protocols/smtp
@load base/protocols/imap
@load base/protocols/pop3
@load-sigs ../signatures/email-dpd.sig
@load ../scripts/tcp-reconstruction
@load ../scripts/securemail-email
@load ../scripts/securemail-certs
