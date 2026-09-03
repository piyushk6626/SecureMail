redef global_hash_seed = "securemail-v0";

@load base/protocols/conn
@load policy/protocols/ssl/ssl-log-ext
@load policy/protocols/ssl/validate-certs
@load ../scripts/tcp-reconstruction
