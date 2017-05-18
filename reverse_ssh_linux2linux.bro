# Reverse SSH Interactive Shell Detection
# © 2015 John B. Althouse III and Jeff Atkinson
# Idea from W.
#
# Detects when multiple characters have been typed into a reverse SSH shell and returned.
# Linux to Linux version 1.1
# This version has been depricated. See Version 2 which is much more performant.
#
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

redef enum Notice::Type += {
  SSH_Reverse_Shell,
};

global lssh_conns:table[string] of count &redef;
global linux_echo:table[string] of count &redef;

event ssh_server_version(c: connection, version: string)
{
  if ( c$uid !in lssh_conns ) 
  {
	lssh_conns[c$uid] = 0;
	linux_echo[c$uid] = 0;
  }
  if ( c$uid !in linux_echo )
  {
    linux_echo[c$uid] = 0;
  }
}

event new_packet(c: connection, p: pkt_hdr)
{ 
if ( ! c?$service || "SSH" !in c$service) { return; }

local is_src = p$ip$src == c$id$orig_h;

if ( is_src == F && p$tcp$dl == 96 && lssh_conns[c$uid] == 0 )
  {
        lssh_conns[c$uid] += 1;
        return;
  }

if ( is_src == T && p$tcp$dl == 96 && lssh_conns[c$uid] == 1 )
{
  	lssh_conns[c$uid] += 1;
	return;
}

if ( is_src == F && p$tcp$dl == 0 && lssh_conns[c$uid] == 2 ) 
{
	lssh_conns[c$uid] += 1;
	return;
}
if ( is_src == F && p$tcp$dl == 96 && lssh_conns[c$uid] >= 3 )
  {
        lssh_conns[c$uid] += 1;
	return;
  }
if ( is_src == T && p$tcp$dl == 96 && lssh_conns[c$uid] >= 4 )
{
	lssh_conns[c$uid] += 1;
	return;
}
if ( is_src == F && p$tcp$dl == 0 && lssh_conns[c$uid] >= 5 ) 
{
	lssh_conns[c$uid] += 1;
	return;
}

if ( is_src == T && p$tcp$dl > 96 && lssh_conns[c$uid] >= 10 )
{
	lssh_conns[c$uid] += 1;
	linux_echo[c$uid] = 1;
}

else { lssh_conns[c$uid] = 0; return; }

if ( c$uid in linux_echo ) 
  {
    if ( linux_echo[c$uid] == 1 ) 
    {
      NOTICE([$note=SSH_Reverse_Shell,
	    $conn = c,
	    $msg = fmt("Active SSH Reverse Shell from Linux: %s to Linux: %s:%s", c$id$orig_h,c$id$resp_h,c$id$resp_p),
	    $sub = "Consecutive characters typed into a reverse SSH shell followed by a return."
	  ]);
     linux_echo[c$uid] = 0;
     lssh_conns[c$uid] = 0;
    }
  }
}
