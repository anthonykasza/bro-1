## THIS SCRIPT NO LONGER WORKS, Metasploit was updated. But feel free to use this as a template.
## Detect Metasploit SSL Sessions (includes /meterpreter/reverse_https and browser exploits with SSL)
##
## (c)2014 John Althouse
## @darkphyber
## <3 to Vlad and Liam
## 
## We're basically looking for [a-z]+[A-Z]{2,} in the L= of the x509 cert where C=US. Simple. :)
## This script can act as a template for many things, feel free to use it.
##

module MSF_SSL;

export {
        redef enum Notice::Type += {
		## Indicates that an SSL certificate was seen which matches the Metasploit SSL
		## cert generation algorithm.
		Metasploit_SSL_Cert,
        };
}

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
	{
        if ( !(cert?$issuer) || (/C=US/ !in cert$issuer) )
              return;
              	## If C=US is not in the cert then stop going down this script
	local conn: connection;
	for ( c in f$conns )
		conn=f$conns[c];
	local metasploit = /[a-z]+[A-Z]{2,}/;
		## This is the regex that matches on MSF's random mixedcase alpha
        local x509_data: table[string] of string = table();
        local parts = split(cert$issuer, /,/);
        for ( part_index in parts )
                {
                local key_val = split1(parts[part_index], /=/);
                if ( 2 in key_val)
                        x509_data[key_val[1]] = key_val[2];
                }
        if ( "C" in x509_data && x509_data["C"] == "US" && "L" in x509_data && metasploit in x509_data["L"] )
                NOTICE([$note=Metasploit_SSL_Cert, $conn=conn,
                        $msg=fmt("Metasploit SSL Detected, random issuer US city '%s'", x509_data["L"]),
                        $sub=cert$issuer,
                        $identifier=cert$issuer]);
        }
