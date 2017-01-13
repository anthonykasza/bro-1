# Reverse SSH Interactive Shell Detection
# © 2015 John B. Althouse III and Jeff Atkinson
# Idea from W.
# DBDB.
#
# Detects when multiple characters have been typed into a reverse SSH shell and returned.
# Mac to Linux version 1.1

global mssh_conns:table[string] of count &redef;
global mac_echo:table[string] of count &redef;

redef enum Notice::Type += {SSH_Reverse_Shell};

event ssh_server_version(c: connection, version: string)
{
  if ( c$uid !in mssh_conns ) 
  {
	mssh_conns[c$uid] = 0;
	mac_echo[c$uid] = 0;
  }
  if ( c$uid !in mac_echo )
  {
    mac_echo[c$uid] = 0;
  }
}

event new_packet(c: connection, p: pkt_hdr)
{
if ( ! c?$service || "SSH" !in c$service) { return; }

local is_src = p$ip$src == c$id$orig_h;

if ( is_src == F && p$tcp$dl == 96 && mssh_conns[c$uid] == 0 )
{
        mssh_conns[c$uid] += 1;
        return;
}
if ( is_src == T && p$tcp$dl == 0 && mssh_conns[c$uid] == 1 )
{
  	mssh_conns[c$uid] += 1;
	return;
}
if ( is_src == T && p$tcp$dl == 96 && mssh_conns[c$uid] == 2 )
{
  	mssh_conns[c$uid] += 1;
	return;
}
if ( is_src == F && p$tcp$dl == 0 && mssh_conns[c$uid] == 3 ) 
{
	mssh_conns[c$uid] += 1;
	return;
}
if ( is_src == F && p$tcp$dl == 96 && mssh_conns[c$uid] >= 4 )
{
        mssh_conns[c$uid] += 1;
	return;
}
if ( is_src == T && p$tcp$dl == 0 && mssh_conns[c$uid] >= 5 )
{
  	mssh_conns[c$uid] += 1;
	return;
}
if ( is_src == T && p$tcp$dl == 96 && mssh_conns[c$uid] >= 6 )
{
	mssh_conns[c$uid] += 1;
	return;
}
if ( is_src == F && p$tcp$dl == 0 && mssh_conns[c$uid] >= 7 ) 
{
	mssh_conns[c$uid] += 1;
	return;
}

if ( is_src == T && p$tcp$dl > 96 && mssh_conns[c$uid] >= 12 )
{
	mssh_conns[c$uid] += 1;
	mac_echo[c$uid] = 1;
}

else { mssh_conns[c$uid] = 0; return; }

if ( c$uid in mac_echo ) 
  {
    if ( mac_echo[c$uid] == 1 ) 
    {
      NOTICE([$note=SSH_Reverse_Shell,
	    $conn = c,
	    $msg = fmt("Active SSH Reverse Shell from Mac: %s to Linux: %s:%s", c$id$orig_h,c$id$resp_h,c$id$resp_p),
	    $sub = "Consecutive characters typed into a reverse SSH shell followed by a return."
	  ]);
     mac_echo[c$uid] = 0;
     mssh_conns[c$uid] = 0;
    }
  }
}
