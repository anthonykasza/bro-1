## Detect Default Metasploit SSL Random Cert (includes /meterpreter/reverse_https and browser exploits with SSL)
## Version 2 (8/2/2015)
## Copywrite 2015 John B. Althouse III
##

module MSF_SSL;

export {
        redef enum Notice::Type += {
                ## Indicates that an SSL certificate was seen which matches the Metasploit SSL
                ## cert generation algorithm.
		Metasploit_SSL_Cert,
        };
}

const falselist += {
	## False positive list
	"CN=localhost",
	"CN=office",
	"CN=default",
	"CN=mail"
	};

event ssl_established(c: connection )
	{
	if ( c$id$resp_h in 10.0.0.0/8 ) { return; }
	if ( ! c$ssl?$subject ) { return; }
	if ( ! c$ssl?$issuer ) { return; }
	if ( c$ssl$subject != c$ssl$issuer ) { return; }
	if ( c$ssl$subject in falselist ) { return; }
	if ( /^CN=[a-z]{2,10}$/ == c$ssl$subject );
	if ( /^.+SHA256$/ == c$ssl$cipher );
                NOTICE([$note=Metasploit_SSL_Cert, $conn=c,
                        $msg=fmt("Metasploit Style Randomly Generated SSL Cert, '%s'", c$ssl$subject),
                        $sub=c$ssl$issuer]);
        }
