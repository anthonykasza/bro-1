## UPDATE OCT. 2017 - THIS NO LONGER WORKS ON LATEST VERSION OF METASPLOIT
##
## Detect Default Metasploit SSL Random Cert (includes /meterpreter/reverse_https and browser exploits with SSL)
## Version 2 (8/2/2015)
## Copywrite 2015 John B. Althouse III
##
##    This program is free software: you can redistribute it and/or modify
##    it under the terms of the GNU General Public License as published by
##    the Free Software Foundation, either version 3 of the License, or
##    any later version.
##
##    This program is distributed in the hope that it will be useful,
##    but WITHOUT ANY WARRANTY; without even the implied warranty of
##    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##    GNU General Public License for more details.
##
##    You should have received a copy of the GNU General Public License
##    along with this program.  If not, see <http://www.gnu.org/licenses/>.

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

event x509_certificate(f: fa_file , cert_ref: opaque of x509 , cert: X509::Certificate )
	{
	for ( cid in f$conns )
	    { if ( cid$resp_h in 10.0.0.0/8 ) { return; } }
	if ( ! cert?$subject ) { return; }
	if ( ! cert?$issuer ) { return; }
	if ( cert$subject != cert$issuer ) { return; }
	if ( cert$subject in falselist ) { return; }
	if ( /^CN=[a-z]{2,10}$/ == cert$subject )
	if ( "sha256WithRSAEncryption" == cert$sig_alg )
                NOTICE([$note=Metasploit_SSL_Cert, $conn=f$conns[cid],
                        $msg=fmt("Metasploit Style Randomly Generated SSL Cert, '%s'", cert$subject),
                        $sub=cert$issuer]);
        }
