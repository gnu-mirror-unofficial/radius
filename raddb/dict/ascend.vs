#
# Ascend dictionary.
#
# Enable by putting the line "$INCLUDE dict/ascend.vs" into
# the main dictionary file.
# Version:	2.00  29-Jun-2001  Oleg Gawriloff <barzog@telecom.by>
#		based on TAOS RADIUS Guide and Reference P/N:7820-0729-004
#		for software version 9.0, january 2001
# Version:	1.00  21-Jul-1997  Jens Glaser <jens@regio.net>
#
VENDOR          Ascend				529

#
#	Ascend specific extensions
#	Used by ASCEND MAX/Pipeline products
#
ATTRIBUTE	Ascend-UU-Info			  7	string		Ascend
ATTRIBUTE	Ascend-User-Priority		  8	integer		Ascend
ATTRIBUTE	Ascend-CIR-Timer		  9	integer		Ascend
ATTRIBUTE	Ascend-FR-08-Mode		 10	integer		Ascend
ATTRIBUTE	Ascend-FR-SVC-Addr		 12	integer		Ascend
ATTRIBUTE	Ascend-NAS-Port-Format		 13	integer		Ascend
ATTRIBUTE	Ascend-ATM-Fault-Management	 14	integer		Ascend
ATTRIBUTE	Ascend-ATM-Loopback-Cell-Loss	 15	integer		Ascend
ATTRIBUTE	Ascend-Ckt-Type			 16	integer		Ascend
ATTRIBUTE	Ascend-SVC-Enabled		 17	integer		Ascend
ATTRIBUTE	Ascend-PW-Expiration		 21	string		Ascend
ATTRIBUTE	Ascend-Auth-Delay		 28     integer		Ascend
ATTRIBUTE	Ascend-X25-Pad-X3-Profile	 29	integer		Ascend
ATTRIBUTE	Ascend-X25-Pad-X3-Parameters	 30	string		Ascend
ATTRIBUTE	Ascend-Tunnel-VRouter-Name	 31	string		Ascend
ATTRIBUTE	Ascend-X25-Reverse-Charging	 32	integer		Ascend
ATTRIBUTE	Ascend-X25-Nui-Prompt		 33 	string		Ascend
ATTRIBUTE	Ascend-X25-Nui-Password-Prompt	 34	string		Ascend
ATTRIBUTE	Ascend-X25-Cug			 35	string		Ascend
ATTRIBUTE	Ascend-X25-Pad-Alias-1		 36	string		Ascend
ATTRIBUTE	Ascend-X25-Pad-Alias-2		 37	string		Ascend
ATTRIBUTE	Ascend-X25-Pad-Alias-3		 38	string		Ascend
ATTRIBUTE	Ascend-X25-X121-Address		 39	string		Ascend
ATTRIBUTE	Ascend-X25-Rpoa			 41	string		Ascend
ATTRIBUTE	Ascend-X25-Pad-Prompt		 42	string		Ascend
ATTRIBUTE	Ascend-X25-Pad-Banner		 43	string		Ascend
ATTRIBUTE	Ascend-X25-Profile-Name		 44	string		Ascend
ATTRIBUTE	Ascend-X25-Nui			 45	string		Ascend
ATTRIBUTE	Ascend-Recv-Name		 45	string		Ascend
ATTRIBUTE	Ascend-Bi-Directional-Auth	 46	integer		Ascend
ATTRIBUTE	Ascend-MTU			 47	integer		Ascend
ATTRIBUTE	Ascend-Filter-Required		 50	integer		Ascend
ATTRIBUTE	Ascend-Traffic-Shaper		 51	integer		Ascend
ATTRIBUTE	Ascend-Private-Route-Table-ID	 54	string		Ascend
ATTRIBUTE	Ascend-Private-Route-Required	 55	integer		Ascend
ATTRIBUTE	Ascend-Cache-Refresh		 56	integer		Ascend
ATTRIBUTE	Ascend-Cache-Time		 57	integer		Ascend
ATTRIBUTE	Ascend-Egress-Enabled		 58 	integer		Ascend
ATTRIBUTE	Ascend-QOS-Upstream		 59	string		Ascend
ATTRIBUTE	Ascend-QOS-Downstream		 60	string		Ascend
ATTRIBUTE	Ascend-ATM-Connect-Vpi		 61	integer		Ascend
ATTRIBUTE	Ascend-ATM-Connect-Vci		 62	integer		Ascend
ATTRIBUTE	Ascend-ATM-Connect-Group	 63	integer		Ascend
ATTRIBUTE	Ascend-ATM-Group		 64 	integer		Ascend
ATTRIBUTE	Ascend-IPX-Header-Compression	 65	integer		Ascend
ATTRIBUTE	Ascend-Calling-Id-Type-Of-Number 66	integer		Ascend
ATTRIBUTE	Ascend-Calling-Id-Numbering-Plan 67	integer		Ascend
ATTRIBUTE	Ascend-Calling-Id-Presentation   68	integer		Ascend
ATTRIBUTE	Ascend-Calling-Id-Screening	 69	integer		Ascend
ATTRIBUTE	Ascend-BIR-Enable		 70	integer		Ascend
ATTRIBUTE	Ascend-BIR-Proxy		 71	integer		Ascend
ATTRIBUTE	Ascend-BIR-Bridge-Group		 72	integer		Ascend
ATTRIBUTE	Ascend-IPSEC-Profile		 73	string		Ascend
ATTRIBUTE	Ascend-PPPoE-Enable		 74	integer		Ascend
ATTRIBUTE	Ascend-Bridge-Non-PPPoE		 75	integer		Ascend
ATTRIBUTE	Ascend-ATM-Direct		 76	integer		Ascend
ATTRIBUTE	Ascend-ATM-Profile		 77	string		Ascend
ATTRIBUTE	Ascend-Client-Priamry-WINS	 78	ipaddr		Ascend
ATTRIBUTE	Ascend-Client-Secondary-WINS	 79	ipaddr		Ascend
ATTRIBUTE	Ascend-Client-Assign-WINS	 80	integer		Ascend
ATTRIBUTE	Ascend-Auth-Type		 81	integer		Ascend
ATTRIBUTE	Ascend-Port-Redir-Protocol	 82	integer		Ascend
ATTRIBUTE	Ascend-Port-Redir-Portnum	 83	integer		Ascend
ATTRIBUTE	Ascend-Port-Redir-Server	 84	ipaddr		Ascend
ATTRIBUTE	Ascend-IP-Pool-Chaining		 85	integer		Ascend
ATTRIBUTE	Ascend-Owner-IP-Addr		 86	ipaddr		Ascend
ATTRIBUTE	Ascend-IP-TOS			 87	integer		Ascend
ATTRIBUTE	Ascend-IP-TOS-Apply-To		 89	integer		Ascend
ATTRIBUTE	Ascend-Filter			 90 	string		Ascend
ATTRIBUTE	Ascend-Telnet-Profile		 91	string		Ascend
ATTRIBUTE	Ascend-Dsl-Rate-Type		 92	integer		Ascend
ATTRIBUTE	Ascend-Redirect-Number		 93	string		Ascend
ATTRIBUTE	Ascend-ATM-Vpi			 94	integer		Ascend
ATTRIBUTE	Ascend-ATM-Vci			 95	integer		Ascend
ATTRIBUTE	Ascend-Source-IP-Check		 96	integer		Ascend
ATTRIBUTE	Ascend-Dsl-Rate-Mode		 97	integer		Ascend
ATTRIBUTE	Ascend-DSL-Upstream-Limit	 98	integer		Ascend
ATTRIBUTE	Ascend-DSL-Downstream-Limit	 99	integer		Ascend
ATTRIBUTE	Ascend-Dsl-CIR-Recv-Limit	100	integer		Ascend
ATTRIBUTE	Ascend-Dsl-CIR-Xmit-Limit	101	integer		Ascend
ATTRIBUTE	Ascend-VRouter-Name		102	string		Ascend
ATTRIBUTE	Ascend-Source-Auth		103	string		Ascend
ATTRIBUTE	Ascend-Private-Route		104	string		Ascend
ATTRIBUTE	Ascend-Numbering-Plan-ID	105	integer		Ascend
ATTRIBUTE	Ascend-FR-Link-Status-DLCI	106	integer		Ascend
ATTRIBUTE	Ascend-Calling-Subaddress	107	integer		Ascend
ATTRIBUTE	Ascend-Callback-Delay		108	integer		Ascend
ATTRIBUTE	Ascend-Endpoint-Disc		109	integer		Ascend
ATTRIBUTE	Ascend-Remote-FW		110	string		Ascend
ATTRIBUTE	Ascend-Multicast-GLeave-Delay	111	integer		Ascend
ATTRIBUTE	Ascend-CBCP-Enable		112	integer		Ascend
ATTRIBUTE	Ascend-CBCP-Mode		113	integer		Ascend
ATTRIBUTE	Ascend-CBCP-Trunk-Group		115	integer		Ascend
ATTRIBUTE	Ascend-Appletalk-Route		116	string		Ascend
ATTRIBUTE	Ascend-Appletalk-Peer-Mode	117	integer		Ascend
ATTRIBUTE	Ascend-Route-Appletalk		118	integer		Ascend
ATTRIBUTE	Ascend-FCP-Parameter		119	string		Ascend
ATTRIBUTE	Ascend-Modem-PortNo		120	integer		Ascend
ATTRIBUTE	Ascend-Modem-SlotNo		121	integer		Ascend
ATTRIBUTE	Ascend-Modem-ShelfNo		122	integer		Ascend
ATTRIBUTE	Ascend-Call-Attempt-Limit	123	integer		Ascend
ATTRIBUTE	Ascend-Call-Block-Duration	124	integer		Ascend
ATTRIBUTE	Ascend-Maximum-Call-Duration	125	integer		Ascend
ATTRIBUTE	Ascend-Route-Preference		126	integer		Ascend
ATTRIBUTE       Ascend-Shared-Profile-Enable    128     integer		Ascend
ATTRIBUTE	Ascend-Primary-Home-Agent	129	string		Ascend
ATTRIBUTE	Ascend-Secondary-Home-Agent	130	string		Ascend
ATTRIBUTE	Ascend-Dialout-Allowed		131	integer		Ascend
ATTRIBUTE	Ascend-Client-Gateway		132	ipaddr		Ascend
ATTRIBUTE	Ascend-BACP-Enable		133	integer		Ascend
ATTRIBUTE	Ascend-DHCP-Maximum-Leases	134	integer		Ascend
ATTRIBUTE	Ascend-Client-Primary-DNS	135	ipaddr		Ascend
ATTRIBUTE	Ascend-Client-Secondary-DNS	136	ipaddr		Ascend
ATTRIBUTE	Ascend-Client-Assign-DNS	137	integer		Ascend
ATTRIBUTE	Ascend-User-Acct-Type		138	integer		Ascend
ATTRIBUTE	Ascend-User-Acct-Host		139	ipaddr		Ascend
ATTRIBUTE	Ascend-User-Acct-Port		140	integer		Ascend
ATTRIBUTE	Ascend-User-Acct-Key		141	string		Ascend
ATTRIBUTE	Ascend-User-Acct-Base		142	integer		Ascend
ATTRIBUTE	Ascend-User-Acct-Time		143	integer		Ascend
ATTRIBUTE	Ascend-Assign-IP-Client		144	ipaddr		Ascend
ATTRIBUTE	Ascend-Assign-IP-Server		145	ipaddr		Ascend
ATTRIBUTE	Ascend-Assign-IP-Global-Pool	146	string		Ascend
ATTRIBUTE	Ascend-DHCP-Reply		147	integer		Ascend
ATTRIBUTE	Ascend-DHCP-Pool-Number		148	integer		Ascend
ATTRIBUTE	Ascend-Expect-Callback		149	integer		Ascend
ATTRIBUTE	Ascend-Event-Type		150	integer		Ascend
ATTRIBUTE	Ascend-Session-Svr-Key		151	string		Ascend
ATTRIBUTE	Ascend-Multicast-Rate-Limit	152	integer		Ascend
ATTRIBUTE	Ascend-IF-Netmask		153	ipaddr		Ascend
ATTRIBUTE	Ascend-Remote-Addr		154	ipaddr		Ascend
ATTRIBUTE	Ascend-Multicast-Client		155	integer		Ascend
ATTRIBUTE	Ascend-FR-Circuit-Name		156	string		Ascend
ATTRIBUTE	Ascend-FR-LinkUp		157	integer		Ascend
ATTRIBUTE	Ascend-FR-Nailed-Grp		158	integer		Ascend
ATTRIBUTE	Ascend-FR-Type			159	integer		Ascend
ATTRIBUTE	Ascend-FR-Link-Mgt		160	integer		Ascend
ATTRIBUTE	Ascend-FR-N391			161	integer		Ascend
ATTRIBUTE	Ascend-FR-DCE-N392		162	integer		Ascend
ATTRIBUTE	Ascend-FR-DTE-N392		163	integer		Ascend
ATTRIBUTE	Ascend-FR-DCE-N393		164	integer		Ascend
ATTRIBUTE	Ascend-FR-DTE-N393		165	integer		Ascend
ATTRIBUTE	Ascend-FR-T391			166	integer		Ascend
ATTRIBUTE	Ascend-FR-T392			167	integer		Ascend
ATTRIBUTE	Ascend-Bridge-Address  	 	168	string		Ascend
ATTRIBUTE       Ascend-TS-Idle-Limit            169     integer		Ascend
ATTRIBUTE       Ascend-TS-Idle-Mode             170     integer		Ascend
ATTRIBUTE	Ascend-DBA-Monitor	 	171	integer		Ascend
ATTRIBUTE	Ascend-Base-Channel-Count 	172	integer		Ascend
ATTRIBUTE	Ascend-Minimum-Channels		173	integer		Ascend
ATTRIBUTE	Ascend-IPX-Route		174	string		Ascend
ATTRIBUTE	Ascend-FT1-Caller		175	integer		Ascend
ATTRIBUTE	Ascend-Backup			176	string		Ascend
ATTRIBUTE	Ascend-Call-Type		177	integer		Ascend
ATTRIBUTE	Ascend-Group			178	string		Ascend
ATTRIBUTE	Ascend-FR-DLCI			179	integer		Ascend
ATTRIBUTE	Ascend-FR-Profile-Name		180	string		Ascend
ATTRIBUTE	Ascend-Ara-PW			181	string		Ascend
ATTRIBUTE	Ascend-IPX-Node-Addr		182	string		Ascend
ATTRIBUTE	Ascend-Home-Agent-IP-Addr	183	ipaddr		Ascend
ATTRIBUTE	Ascend-Home-Agent-Password	184	string		Ascend
ATTRIBUTE	Ascend-Home-Network-Name	185	string		Ascend
ATTRIBUTE	Ascend-Home-Agent-UDP-Port	186	integer		Ascend
ATTRIBUTE	Ascend-Multilink-ID		187	integer		Ascend
ATTRIBUTE	Ascend-Num-In-Multilink		188	integer		Ascend
ATTRIBUTE	Ascend-First-Dest		189	ipaddr		Ascend
ATTRIBUTE	Ascend-Pre-Input-Octets		190	integer		Ascend
ATTRIBUTE	Ascend-Pre-Output-Octets	191	integer		Ascend
ATTRIBUTE	Ascend-Pre-Input-Packets	192	integer		Ascend
ATTRIBUTE	Ascend-Pre-Output-Packets	193	integer		Ascend
ATTRIBUTE	Ascend-Maximum-Time		194	integer		Ascend
ATTRIBUTE	Ascend-Disconnect-Cause		195	integer		Ascend
ATTRIBUTE	Ascend-Connect-Progress		196	integer		Ascend
ATTRIBUTE	Ascend-Data-Rate		197	integer		Ascend
ATTRIBUTE	Ascend-PreSession-Time		198	integer		Ascend
ATTRIBUTE	Ascend-Token-Idle		199	integer		Ascend
ATTRIBUTE	Ascend-Token-Immediate		200	integer		Ascend
ATTRIBUTE	Ascend-Require-Auth		201	integer		Ascend
ATTRIBUTE	Ascend-Number-Sessions		202	string		Ascend
ATTRIBUTE	Ascend-Authen-Alias		203	string		Ascend
ATTRIBUTE	Ascend-Token-Expiry		204	integer		Ascend
ATTRIBUTE	Ascend-Menu-Selector		205	string		Ascend
ATTRIBUTE	Ascend-Menu-Item		206	string		Ascend
ATTRIBUTE	Ascend-PW-Warntime		207	integer		Ascend
ATTRIBUTE	Ascend-PW-Lifetime		208	integer		Ascend
ATTRIBUTE	Ascend-IP-Direct		209	ipaddr		Ascend
ATTRIBUTE	Ascend-PPP-VJ-Slot-Comp		210	integer		Ascend
ATTRIBUTE	Ascend-PPP-VJ-1172		211	integer		Ascend
ATTRIBUTE	Ascend-PPP-Async-Map		212	integer		Ascend
ATTRIBUTE	Ascend-Third-Prompt		213	string		Ascend
ATTRIBUTE	Ascend-Send-Secret		214	string		Ascend
ATTRIBUTE	Ascend-Receive-Secret		215	string		Ascend
ATTRIBUTE	Ascend-IPX-Peer-Mode		216	integer		Ascend
ATTRIBUTE	Ascend-IP-Pool-Definition	217	string		Ascend
ATTRIBUTE	Ascend-Assign-IP-Pool		218	integer		Ascend
ATTRIBUTE	Ascend-FR-Direct		219	integer		Ascend
ATTRIBUTE	Ascend-FR-Direct-Profile	220	string		Ascend
ATTRIBUTE	Ascend-FR-Direct-DLCI		221	integer		Ascend
ATTRIBUTE	Ascend-Handle-IPX		222	integer		Ascend
ATTRIBUTE	Ascend-Netware-timeout		223	integer		Ascend
ATTRIBUTE	Ascend-IPX-Alias		224	integer		Ascend
ATTRIBUTE	Ascend-Metric			225	integer		Ascend
ATTRIBUTE	Ascend-PRI-Number-Type		226	integer		Ascend
ATTRIBUTE	Ascend-Dial-Number		227	string		Ascend
ATTRIBUTE	Ascend-Route-IP			228	integer		Ascend
ATTRIBUTE	Ascend-Route-IPX		229	integer		Ascend
ATTRIBUTE	Ascend-Bridge			230	integer		Ascend
ATTRIBUTE	Ascend-Send-Auth		231	integer		Ascend
ATTRIBUTE	Ascend-Send-Passwd		232	string		Ascend
ATTRIBUTE	Ascend-Link-Compression		233	integer		Ascend
ATTRIBUTE	Ascend-Target-Util		234	integer		Ascend
ATTRIBUTE	Ascend-Maximum-Channels		235	integer		Ascend
ATTRIBUTE	Ascend-Inc-Channel-Count	236	integer		Ascend
ATTRIBUTE	Ascend-Dec-Channel-Count	237	integer		Ascend
ATTRIBUTE	Ascend-Seconds-Of-History	238	integer		Ascend
ATTRIBUTE	Ascend-History-Weigh-Type	239	integer		Ascend
ATTRIBUTE	Ascend-Add-Seconds		240	integer		Ascend
ATTRIBUTE	Ascend-Remove-Seconds		241	integer		Ascend
ATTRIBUTE	Ascend-Data-Filter		242	abinary		Ascend
ATTRIBUTE	Ascend-Call-Filter		243	abinary		Ascend
ATTRIBUTE	Ascend-Idle-Limit		244	integer		Ascend
ATTRIBUTE	Ascend-Preempt-Limit		245	integer		Ascend
ATTRIBUTE	Ascend-Callback			246	integer		Ascend
ATTRIBUTE	Ascend-Data-Svc			247	integer		Ascend
ATTRIBUTE	Ascend-Force-56			248	integer		Ascend
ATTRIBUTE	Ascend-Billing-Number		249	string		Ascend
ATTRIBUTE	Ascend-Call-By-Call		250	integer		Ascend
ATTRIBUTE	Ascend-Transit-Number		251	string		Ascend
ATTRIBUTE	Ascend-Host-Info		252	string		Ascend
ATTRIBUTE	Ascend-PPP-Address		253	ipaddr		Ascend
ATTRIBUTE	Ascend-MPP-Idle-Percent		254	integer		Ascend
ATTRIBUTE	Ascend-Xmit-Rate		255	integer		Ascend

# Ascend protocols
VALUE		Service-Type		Dialout-Framed-User	5
VALUE		Framed-Protocol		ARA			255
VALUE		Framed-Protocol		MPP			256
VALUE		Framed-Protocol		EURAW			257
VALUE		Framed-Protocol		EUUI			258
VALUE		Framed-Protocol		X25			259
VALUE		Framed-Protocol		COMB			260
VALUE		Framed-Protocol		FR			261
VALUE		Framed-Protocol		MP			262
VALUE		Framed-Protocol		FR-CIR			263


#
#	Ascend specific extensions
#	Used by ASCEND MAX/Pipeline products (see above)
#
VALUE		Ascend-FR-08-Mode	FR-08-Mode-No		0
VALUE           Ascend-FR-08-Mode       FR-08-Mode-Yes		1
VALUE		Ascend-SVC-Enabled	Ascend-SVC-Enabled-No	0
VALUE		Ascend-SVC-Enabled	Ascend-SVC-Enabled-Yes	1
VALUE		Ascend-X25-Reverse-Charging Reverse-Charging-No 0
VALUE		Ascend-X25-Reverse-Charging Reverse-Charging-Yes 1
VALUE		Ascend-X25-Pad-X3-Profile CRT			0
VALUE		Ascend-X25-Pad-X3-Profile INFONET		1
VALUE		Ascend-X25-Pad-X3-Profile DEFAULT		2
VALUE		Ascend-X25-Pad-X3-Profile SCEN			3
VALUE		Ascend-X25-Pad-X3-Profile CC_SSP		4
VALUE		Ascend-X25-Pad-X3-Profile CC_TSP		5
VALUE		Ascend-X25-Pad-X3-Profile HARDCOPY		6
VALUE		Ascend-X25-Pad-X3-Profile HDX			7
VALUE		Ascend-X25-Pad-X3-Profile SHARK			8
VALUE		Ascend-X25-Pad-X3-Profile POS			9
VALUE		Ascend-X25-Pad-X3-Profile NULL			10
VALUE		Ascend-X25-Pad-X3-Profile CUSTOM		11
VALUE		Ascend-NAS-Port-Format	Unknown			0
VALUE		Ascend-NAS-Port-Format  2_4_6_4			1
VALUE		Ascend-NAS-Port-Format  2_4_5_5			2
VALUE		Ascend-NAS-Port-Format  1_2_2			3
VALUE		Ascend-NAS-Port-Format  0_6_5_5			4
VALUE		Ascend-ATM-Fault-Management VC-No-Loopback	0
VALUE           Ascend-ATM-Fault-Management VC-Segment-Loopback 1
VALUE           Ascend-ATM-Fault-Management VC-End-To-End-Loopback 2
VALUE		Ascend-BIR-Enable	BIR-Enable-No		0
VALUE		Ascend-BIR-Enable	BIR-Enable-Yes		1
VALUE		Ascend-BIR-Proxy	BIR-Proxy-No		0
VALUE		Ascend-BIR-Proxy	BIR-Proxy-Yes		1
VALUE		Ascend-PPPoE-Enable	PPPoE-No		0
VALUE		Ascend-PPPoE-Enable	PPPoE-Yes		1
VALUE		Ascend-Bridge-Non-PPPoE Bridge-Non-PPPoE-No	0
VALUE		Ascend-Bridge-Non-PPPoE Bridge-Non-PPPoE-Yes	1	
VALUE		Ascend-Bi-Directional-Auth Bi-Directinal-Auth-None 0
VALUE           Ascend-Bi-Directional-Auth Bi-Directional-Auth-Allowed 1
VALUE           Ascend-Bi-Directional-Auth Bi-Directional-Auth-Required 2
VALUE		Ascend-Filter-Required	Required-No		0
VALUE           Ascend-Filter-Required  Required-Yes		1
VALUE		Ascend-Private-Route-Required Required-No	0
VALUE		Ascend-Private-Route-Required Required-Yes	1
VALUE		Ascend-Cache-Refresh	Refresh-No		0
VALUE		Ascend-Cache-Refresh	Refresh-Yes		1
VALUE	Ascend-IPX-Header-Compression	Ascend-IPX-Header-Compression-No 0
VALUE   Ascend-IPX-Header-Compression   Ascend-IPX-Header-Compression-Yes 1
VALUE		Ascend-Calling-Id-Type-Of-Number Unknown	0
VALUE           Ascend-Calling-Id-Type-Of-Number International-Number 1
VALUE           Ascend-Calling-Id-Type-Of-Number National-Number 2
VALUE           Ascend-Calling-Id-Type-Of-Number Network-Specific 3
VALUE           Ascend-Calling-Id-Type-Of-Number Subscriber-Number 4
VALUE           Ascend-Calling-Id-Type-Of-Number Abbreviated-Number 6
VALUE		Ascend-Calling-Id-Numbering-Plan Unknown	0
VALUE		Ascend-Calling-Id-Numbering-Plan ISDN-Telephony 1
VALUE		Ascend-Calling-Id-Numbering-Plan Data		3
VALUE		Ascend-Calling-Id-Numbering-Plan Telex		4
VALUE		Ascend-Calling-Id-Numbering-Plan National	8
VALUE		Ascend-Calling-Id-Numbering-Plan Private	9
VALUE		Ascend-Calling-Id-Presentation	Allowed		0
VALUE           Ascend-Calling-Id-Presentation  Restricted	1
VALUE           Ascend-Calling-Id-Presentation  Number-Not-Availbale 2
VALUE		Ascend-Calling-Id-Screening	User-Not-Screened 0
VALUE		Ascend-Calling-Id-Screening	User-Provided-Passed 1
VALUE		Ascend-Calling-Id-Screening	User-Provided-Failed 2
VALUE		Ascend-Calling-Id-Screening	Network-Provided	3
VALUE		Ascend-Egress-Enabled	Egress-Enable-No	0
VALUE		Ascend-Egress-Enabled	Egress-Enable-Yes	1
VALUE		Ascend-Appletalk-Peer-Mode Appletalk-Peer-Router 0
VALUE		Ascend-Appletalk-Peer-Mode Appletalk-Peer-Dialin 1
VALUE		Ascend-Route-Appletalk	Route-AppleTalk-No	0
VALUE		Ascend-Route-Appletalk	Route-AppleTalk-Yes	1
VALUE		Ascend-CBCP-Enable	CBCP-Not-Enabled	0
VALUE		Ascend-CBCP-Enable	CBCP-Enabled		1
VALUE		Ascend-CBCP-Mode	CBCP-No-Callback	1
VALUE		Ascend-CBCP-Mode	CBCP-User-Callback	2
VALUE           Ascend-CBCP-Mode        CBCP-Profile-Callback	3
VALUE           Ascend-CBCP-Mode        CBCP-Any-Or-No		7
VALUE		Ascend-Dsl-Rate-Type	Rate-Type-Disabled	0
VALUE		Ascend-Dsl-Rate-Type	Rate-Type-Sdsl		1
VALUE		Ascend-Dsl-Rate-Type	Rate-Type-AdslCap	2
VALUE		Ascend-Dsl-Rate-Type	Rate-Type-AdslDmtCell	3
VALUE		Ascend-Dsl-Rate-Type	Rate-Type-AdslDmt	4
VALUE		Ascend-Dsl-Rate-Mode	Rate-Mode-AutoBaud	1
VALUE		Ascend-Dsl-Rate-Mode	Rate-Mode-Single	2
VALUE		Ascend-Source-IP-Check	Source-IP-Check-No	0
VALUE		Ascend-Source-IP-Check	Source-IP-Check-Yes	1
VALUE		Ascend-Numbering-Plan-ID Unknown-Numbering-Plan 0
VALUE		Ascend-Numbering-Plan-ID ISDN-Numbering-Plan	1
VALUE		Ascend-Numbering-Plan-ID Private-Numbering-Plan 9
VALUE		Ascend-ATM-Direct	ATM-Direct-No		0
VALUE		Ascend-ATM-Direct	ATM-Direct-Yes		1
VALUE		Ascend-Auth-Type	Auth-None		0
VALUE		Ascend-Auth-Type	Auth-Default		1
VALUE		Ascend-Auth-Type	Auth-Any		2
VALUE		Ascend-Auth-Type	Auth-PAP		3
VALUE		Ascend-Auth-Type	Auth-CHAP		4
VALUE		Ascend-Auth-Type	Auth-MS-CHAP		5
VALUE		Ascend-Port-Redir-Protocol Ascend-Proto-TCP	6
VALUE		Ascend-Port-Redir-Protocol Ascend-Proto-UDP	17
VALUE		Ascend-IP-Pool-Chaining	IP-Pool-Chaining-No	0
VALUE           Ascend-IP-Pool-Chaining IP-Pool-Chaining-Yes	1
VALUE		Ascend-IP-TOS		IP-TOS-Normal		0
VALUE		Ascend-IP-TOS		IP-TOS-Disabled		1
VALUE		Ascend-IP-TOS		IP-TOS-Cost		2
VALUE		Ascend-IP-TOS		IP-TOS-Reliability	4
VALUE		Ascend-IP-TOS		IP-TOS-Throughput	8
VALUE		Ascend-IP-TOS		IP-TOS-Latency		16
VALUE		Ascend-IP-TOS-Precedence IP-TOS-Precedence-Pri-Normal 0
VALUE		Ascend-IP-TOS-Precedence IP-TOS-Precedence-Pri-One 32
VALUE		Ascend-IP-TOS-Precedence IP-TOS-Precedence-Pri-Two 64
VALUE		Ascend-IP-TOS-Precedence IP-TOS-Precedence-Pri-Three 96
VALUE		Ascend-IP-TOS-Precedence IP-TOS-Precedence-Pri-Four 128
VALUE		Ascend-IP-TOS-Precedence IP-TOS-Precedence-Pri-Five 160
VALUE		Ascend-IP-TOS-Precedence IP-TOS-Precedence-Pri-Six 192
VALUE		Ascend-IP-TOS-Precedence IP-TOS-Precedence-Pri-Seven 224
VALUE		Ascend-IP-TOS-Apply-To  IP-TOS-Apply-To-Incoming 1024
VALUE		Ascend-IP-TOS-Apply-To  IP-TOS-Apply-To-Outgoing 2048
VALUE		Ascend-IP-TOS-Apply-To  IP-TOS-Apply-To-Both	3072
VALUE		Ascend-FR-Direct	FR-Direct-No		0
VALUE		Ascend-FR-Direct	FR-Direct-Yes		1
VALUE		Ascend-Handle-IPX	Handle-IPX-None		0
VALUE		Ascend-Handle-IPX	Handle-IPX-Client	1
VALUE		Ascend-Handle-IPX	Handle-IPX-Server	2
VALUE		Ascend-IPX-Peer-Mode	IPX-Peer-Router		0
VALUE		Ascend-IPX-Peer-Mode	IPX-Peer-Dialin		1
VALUE		Ascend-Call-Type	Switched		0
VALUE		Ascend-Call-Type	Nailed			1
VALUE		Ascend-Call-Type	Nailed/Mpp		2
VALUE		Ascend-Call-Type	Perm/Switched		3
VALUE		Ascend-Call-Type	AO/DI			6
VALUE		Ascend-Call-Type	MegaMax			7
VALUE		Ascend-FT1-Caller	FT1-No			0
VALUE		Ascend-FT1-Caller	FT1-Yes			1
VALUE		Ascend-PRI-Number-Type	Unknown-Number		0
VALUE		Ascend-PRI-Number-Type	Intl-Number		1
VALUE		Ascend-PRI-Number-Type	National-Number		2
VALUE		Ascend-PRI-Number-Type	Net-Specific-Number	3
VALUE		Ascend-PRI-Number-Type	Local-Number		4
VALUE		Ascend-PRI-Number-Type	Abbrev-Number		5
VALUE		Ascend-Route-IP		Route-IP-No		0
VALUE		Ascend-Route-IP		Route-IP-Yes		1
VALUE		Ascend-Route-IPX	Route-IPX-No		0
VALUE		Ascend-Route-IPX	Route-IPX-Yes		1
VALUE		Ascend-Bridge		Bridge-No		0
VALUE		Ascend-Bridge		Bridge-Yes		1
VALUE  		Ascend-TS-Idle-Mode     TS-Idle-None		0
VALUE	  	Ascend-TS-Idle-Mode     TS-Idle-Input		1
VALUE  		Ascend-TS-Idle-Mode     TS-Idle-Input-Output	2
VALUE		Ascend-Send-Auth	Send-Auth-None		0
VALUE		Ascend-Send-Auth	Send-Auth-PAP		1
VALUE		Ascend-Send-Auth	Send-Auth-CHAP		2
VALUE		Ascend-Send-Auth	Send-Auth-MS-CHAP	3
VALUE		Ascend-Link-Compression	Link-Comp-None		0
VALUE		Ascend-Link-Compression	Link-Comp-Stac		1
VALUE		Ascend-Link-Compression	Link-Comp-Stac-Draft-9	2
VALUE		Ascend-Link-Compression	Link-Comp-MS-Stac	3
VALUE		Ascend-History-Weigh-Type	History-Constant	0
VALUE		Ascend-History-Weigh-Type	History-Linear		1
VALUE		Ascend-History-Weigh-Type	History-Quadratic	2
VALUE		Ascend-Callback		Callback-No		0
VALUE		Ascend-Callback		Callback-Yes		1
VALUE		Ascend-Expect-Callback	Expect-Callback-No	0
VALUE		Ascend-Expect-Callback	Expect-Callback-Yes	1
VALUE		Ascend-Data-Svc		Switched-Voice-Bearer	0
VALUE		Ascend-Data-Svc		Switched-56KR		1
VALUE		Ascend-Data-Svc		Switched-64K		2
VALUE		Ascend-Data-Svc		Switched-64KR		3
VALUE		Ascend-Data-Svc		Switched-56K		4
VALUE		Ascend-Data-Svc		Switched-384KR		5
VALUE		Ascend-Data-Svc		Switched-384K		6
VALUE		Ascend-Data-Svc		Switched-1536K		7
VALUE		Ascend-Data-Svc		Switched-1536KR		8
VALUE		Ascend-Data-Svc		Switched-128K		9
VALUE		Ascend-Data-Svc		Switched-192K		10
VALUE		Ascend-Data-Svc		Switched-256K		11
VALUE		Ascend-Data-Svc		Switched-320K		12
VALUE		Ascend-Data-Svc		Switched-384K-MR	13
VALUE		Ascend-Data-Svc		Switched-448K		14
VALUE		Ascend-Data-Svc		Switched-512K		15
VALUE		Ascend-Data-Svc		Switched-576K		16
VALUE		Ascend-Data-Svc		Switched-640K		17
VALUE		Ascend-Data-Svc		Switched-704K		18
VALUE		Ascend-Data-Svc		Switched-768K		19
VALUE		Ascend-Data-Svc		Switched-832K		20
VALUE		Ascend-Data-Svc		Switched-896K		21
VALUE		Ascend-Data-Svc		Switched-960K		22
VALUE		Ascend-Data-Svc		Switched-1024K		23
VALUE		Ascend-Data-Svc		Switched-1088K		24
VALUE		Ascend-Data-Svc		Switched-1152K		25
VALUE		Ascend-Data-Svc		Switched-1216K		26
VALUE		Ascend-Data-Svc		Switched-1280K		27
VALUE		Ascend-Data-Svc		Switched-1344K		28
VALUE		Ascend-Data-Svc		Switched-1408K		29
VALUE		Ascend-Data-Svc		Switched-1472K		30
VALUE		Ascend-Data-Svc		Switched-1600K		31
VALUE		Ascend-Data-Svc		Switched-1664K		32
VALUE		Ascend-Data-Svc		Switched-1728K		33
VALUE		Ascend-Data-Svc		Switched-1792K		34
VALUE		Ascend-Data-Svc		Switched-1856K		35
VALUE		Ascend-Data-Svc		Switched-1920K		36
VALUE		Ascend-Data-Svc		Switched-inherited	37
VALUE		Ascend-Data-Svc		Switched-restricted-bearer-x30  38
VALUE		Ascend-Data-Svc		Switched-clear-bearer-v110	39
VALUE		Ascend-Data-Svc		Switched-restricted-64-x30	40
VALUE		Ascend-Data-Svc		Switched-clear-56-v110		41
VALUE		Ascend-Data-Svc		Switched-modem			42
VALUE		Ascend-Data-Svc		Switched-atmodem		43
VALUE		Ascend-Data-Svc		Switched-V110-24-56	45
VALUE           Ascend-Data-Svc         Switched-V110-48-56	46
VALUE           Ascend-Data-Svc         Switched-V110-96-56	47
VALUE           Ascend-Data-Svc         Switched-V110-192-56	48
VALUE           Ascend-Data-Svc         Switched-V110-384-56	49
VALUE           Ascend-Data-Svc         Switched-V110-24-56R	50
VALUE           Ascend-Data-Svc         Switched-V110-48-56R	51
VALUE           Ascend-Data-Svc         Switched-V110-96-56R	52
VALUE           Ascend-Data-Svc         Switched-V110-192-56R	53
VALUE           Ascend-Data-Svc         Switched-V110-384-56R	54
VALUE           Ascend-Data-Svc         Switched-V110-24-64	55
VALUE           Ascend-Data-Svc		Switched-V110-48-64	56		
VALUE           Ascend-Data-Svc		Switched-V110-96-64	57
VALUE           Ascend-Data-Svc		Switched-V110-192-64	58
VALUE           Ascend-Data-Svc		Switched-V110-384-64	59
VALUE           Ascend-Data-Svc		Switched-V110-24-64R	60
VALUE           Ascend-Data-Svc		Switched-V110-48-64R	61
VALUE           Ascend-Data-Svc		Switched-V110-96-64R	62
VALUE           Ascend-Data-Svc		Switched-V110-192-64R	63
VALUE           Ascend-Data-Svc		Switched-V110-384-64R	64
VALUE           Ascend-Data-Svc 	Switched-POTS		68
VALUE           Ascend-Data-Svc         Switched-ATM		69
VALUE           Ascend-Data-Svc         Switched-FR		70 
VALUE		Ascend-Data-Svc		Nailed-56KR		1
VALUE		Ascend-Data-Svc		Nailed-64K		2
VALUE		Ascend-Force-56		Force-56-No		0
VALUE		Ascend-Force-56		Force-56-Yes		1
VALUE		Ascend-PW-Lifetime	Lifetime-In-Days	0
VALUE		Ascend-PW-Warntime	Days-Of-Warning		0
VALUE		Ascend-PPP-VJ-1172	PPP-VJ-1172		1
VALUE		Ascend-PPP-VJ-Slot-Comp	VJ-Slot-Comp-No		1
VALUE		Ascend-Require-Auth	Not-Require-Auth	0
VALUE		Ascend-Require-Auth	Require-Auth		1
VALUE		Ascend-Token-Immediate	Tok-Imm-No		0
VALUE		Ascend-Token-Immediate	Tok-Imm-Yes		1
VALUE		Ascend-DBA-Monitor	DBA-Transmit		0
VALUE 		Ascend-DBA-Monitor	DBA-Transmit-Recv	1
VALUE		Ascend-DBA-Monitor	DBA-None		2
VALUE		Ascend-FR-Type		Ascend-FR-DTE		0
VALUE		Ascend-FR-Type		Ascend-FR-DCE		1
VALUE		Ascend-FR-Type		Ascend-FR-NNI		2
VALUE		Ascend-FR-Link-Mgt	Ascend-FR-No-Link-Mgt	0
VALUE		Ascend-FR-Link-Mgt	Ascend-FR-T1-617D	1
VALUE		Ascend-FR-Link-Mgt	Ascend-FR-Q-933A	2
VALUE		Ascend-FR-LinkUp	Ascend-LinkUp-Default	0
VALUE		Ascend-FR-LinkUp	Ascend-LinkUp-AlwaysUp	1
VALUE		Ascend-Multicast-Client	Multicast-No		0
VALUE		Ascend-Multicast-Client	Multicast-Yes		1
VALUE		Ascend-User-Acct-Type	Ascend-User-Acct-None	0
VALUE		Ascend-User-Acct-Type	Ascend-User-Acct-User	1
VALUE		Ascend-User-Acct-Type	Ascend-User-Acct-User-Default	2
VALUE		Ascend-User-Acct-Base	Base-10			0
VALUE		Ascend-User-Acct-Base	Base-16			1
VALUE		Ascend-DHCP-Reply	DHCP-Reply-No		0
VALUE		Ascend-DHCP-Reply	DHCP-Reply-Yes		1
VALUE		Ascend-Client-Assign-WINS	WINS-Assign-No	0
VALUE		Ascend-Client-Assign-WINS	WINS-Assign-Yes	1
VALUE		Ascend-Client-Assign-DNS	DNS-Assign-No	0
VALUE		Ascend-Client-Assign-DNS	DNS-Assign-Yes	1
VALUE		Ascend-Event-Type	Ascend-ColdStart	1
VALUE		Ascend-Event-Type	Ascend-Session-Event	2
VALUE		Ascend-BACP-Enable	BACP-No			0
VALUE		Ascend-BACP-Enable	BACP-Yes		1
VALUE		Ascend-Dialout-Allowed	Dialout-Not-Allowed	0
VALUE		Ascend-Dialout-Allowed	Dialout-Allowed		1
VALUE		Ascend-Shared-Profile-Enable    Shared-Profile-No       0
VALUE		Ascend-Shared-Profile-Enable    Shared-Profile-Yes      1
#VALUE		Ascend-Temporary-Rtes	Temp-Rtes-No		0
#VALUE		Ascend-Temporary-Rtes	Temp-Rtes-Yes		1
