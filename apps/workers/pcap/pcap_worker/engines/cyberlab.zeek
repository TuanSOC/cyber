# Zeek policy for offline capture analysis (loaded after Zeek's default base scripts).
@load policy/protocols/conn/community-id-logging
@load policy/protocols/ssl/validate-certs
@load policy/frameworks/files/hash-all-files

redef LogAscii::use_json = T;
redef ignore_checksums = T;
redef Site::local_nets += { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 };
