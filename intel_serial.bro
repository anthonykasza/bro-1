## Adds x509 certificate serial numbers to the Intel Framework as type Intel::CERT_SERIAL
## (c)2014 John Althouse
##

@load base/frameworks/intel
@load base/files/x509
@load policy/frameworks/intel/seen/where-locations

module Intel;

export {
    redef enum Intel::Type += { Intel::CERT_SERIAL };
}

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
	{
	Intel::seen([$indicator=cert$serial, $indicator_type=Intel::CERT_SERIAL, $f=f, $where=X509::IN_CERT]);
	}
