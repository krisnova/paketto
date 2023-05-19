#ifndef PK_KNOWN
#define PK_KNOWN
struct pk_service
{
	char serv[64];
	int   port;
	char protocol[4];
};


struct pk_service knownports[1150] = {
   "tcpmux", 1, "tcp",
   "compressnet", 2, "tcp",
   "compressnet", 3, "tcp",
   "rje", 5, "tcp",
   "echo", 7, "tcp",
   "discard", 9, "tcp",
   "systat", 11, "tcp",
   "daytime", 13, "tcp",
   "netstat", 15, "tcp",
   "qotd", 17, "tcp",
   "msp", 18, "tcp",
   "chargen", 19, "tcp",
   "ftp-data", 20, "tcp",
   "ftp", 21, "tcp",
   "ssh", 22, "tcp",
   "telnet", 23, "tcp",
   "priv-mail", 24, "tcp",
   "smtp", 25, "tcp",
   "nsw-fe", 27, "tcp",
   "msg-icp", 29, "tcp",
   "msg-auth", 31, "tcp",
   "dsp", 33, "tcp",
   "priv-print", 35, "tcp",
   "time", 37, "tcp",
   "rap", 38, "tcp",
   "rlp", 39, "tcp",
   "graphics", 41, "tcp",
   "nameserver", 42, "tcp",
   "whois", 43, "tcp",
   "mpm-flags", 44, "tcp",
   "mpm", 45, "tcp",
   "mpm-snd", 46, "tcp",
   "ni-ftp", 47, "tcp",
   "auditd", 48, "tcp",
   "tacacs", 49, "tcp",
   "re-mail-ck", 50, "tcp",
   "la-maint", 51, "tcp",
   "xns-time", 52, "tcp",
   "domain", 53, "tcp",
   "xns-ch", 54, "tcp",
   "isi-gl", 55, "tcp",
   "xns-auth", 56, "tcp",
   "priv-term", 57, "tcp",
   "xns-mail", 58, "tcp",
   "priv-file", 59, "tcp",
   "ni-mail", 61, "tcp",
   "acas", 62, "tcp",
   "via-ftp", 63, "tcp",
   "covia", 64, "tcp",
   "tacacs-ds", 65, "tcp",
   "sql*net", 66, "tcp",
   "dhcpserver", 67, "tcp",
   "dhcpclient", 68, "tcp",
   "tftp", 69, "tcp",
   "gopher", 70, "tcp",
   "netrjs-1", 71, "tcp",
   "netrjs-2", 72, "tcp",
   "netrjs-3", 73, "tcp",
   "netrjs-4", 74, "tcp",
   "priv-dial", 75, "tcp",
   "deos", 76, "tcp",
   "priv-rje", 77, "tcp",
   "vettcp", 78, "tcp",
   "finger", 79, "tcp",
   "http", 80, "tcp",
   "hosts2-ns", 81, "tcp",
   "xfer", 82, "tcp",
   "mit-ml-dev", 83, "tcp",
   "ctf", 84, "tcp",
   "mit-ml-dev", 85, "tcp",
   "mfcobol", 86, "tcp",
   "priv-term-l", 87, "tcp",
   "kerberos-sec", 88, "tcp",
   "su-mit-tg", 89, "tcp",
   "dnsix", 90, "tcp",
   "mit-dov", 91, "tcp",
   "npp", 92, "tcp",
   "dcp", 93, "tcp",
   "objcall", 94, "tcp",
   "supdup", 95, "tcp",
   "dixie", 96, "tcp",
   "swift-rvf", 97, "tcp",
   "linuxconf", 98, "tcp",
   "metagram", 99, "tcp",
   "newacct", 100, "tcp",
   "hostname", 101, "tcp",
   "iso-tsap", 102, "tcp",
   "gppitnp", 103, "tcp",
   "acr-nema", 104, "tcp",
   "csnet-ns", 105, "tcp",
   "pop3pw", 106, "tcp",
   "rtelnet", 107, "tcp",
   "snagas", 108, "tcp",
   "pop-2", 109, "tcp",
   "pop-3", 110, "tcp",
   "sunrpc", 111, "tcp",
   "mcidas", 112, "tcp",
   "auth", 113, "tcp",
   "audionews", 114, "tcp",
   "sftp", 115, "tcp",
   "ansanotify", 116, "tcp",
   "uucp-path", 117, "tcp",
   "sqlserv", 118, "tcp",
   "nntp", 119, "tcp",
   "cfdptkt", 120, "tcp",
   "erpc", 121, "tcp",
   "smakynet", 122, "tcp",
   "ntp", 123, "tcp",
   "ansatrader", 124, "tcp",
   "locus-map", 125, "tcp",
   "unitary", 126, "tcp",
   "locus-con", 127, "tcp",
   "gss-xlicen", 128, "tcp",
   "pwdgen", 129, "tcp",
   "cisco-fna", 130, "tcp",
   "cisco-tna", 131, "tcp",
   "cisco-sys", 132, "tcp",
   "statsrv", 133, "tcp",
   "ingres-net", 134, "tcp",
   "loc-srv", 135, "tcp",
   "profile", 136, "tcp",
   "netbios-ns", 137, "tcp",
   "netbios-dgm", 138, "tcp",
   "netbios-ssn", 139, "tcp",
   "emfis-data", 140, "tcp",
   "emfis-cntl", 141, "tcp",
   "bl-idm", 142, "tcp",
   "imap2", 143, "tcp",
   "news", 144, "tcp",
   "uaac", 145, "tcp",
   "iso-tp0", 146, "tcp",
   "iso-ip", 147, "tcp",
   "cronus", 148, "tcp",
   "aed-512", 149, "tcp",
   "sql-net", 150, "tcp",
   "hems", 151, "tcp",
   "bftp", 152, "tcp",
   "sgmp", 153, "tcp",
   "netsc-prod", 154, "tcp",
   "netsc-dev", 155, "tcp",
   "sqlsrv", 156, "tcp",
   "knet-cmp", 157, "tcp",
   "pcmail-srv", 158, "tcp",
   "nss-routing", 159, "tcp",
   "sgmp-traps", 160, "tcp",
   "snmp", 161, "tcp",
   "snmptrap", 162, "tcp",
   "cmip-man", 163, "tcp",
   "cmip-agent", 164, "tcp",
   "xns-courier", 165, "tcp",
   "s-net", 166, "tcp",
   "namp", 167, "tcp",
   "rsvd", 168, "tcp",
   "send", 169, "tcp",
   "print-srv", 170, "tcp",
   "multiplex", 171, "tcp",
   "cl-1", 172, "tcp",
   "xyplex-mux", 173, "tcp",
   "mailq", 174, "tcp",
   "vmnet", 175, "tcp",
   "genrad-mux", 176, "tcp",
   "xdmcp", 177, "tcp",
   "nextstep", 178, "tcp",
   "bgp", 179, "tcp",
   "ris", 180, "tcp",
   "unify", 181, "tcp",
   "audit", 182, "tcp",
   "ocbinder", 183, "tcp",
   "ocserver", 184, "tcp",
   "remote-kis", 185, "tcp",
   "kis", 186, "tcp",
   "aci", 187, "tcp",
   "mumps", 188, "tcp",
   "qft", 189, "tcp",
   "gacp", 190, "tcp",
   "prospero", 191, "tcp",
   "osu-nms", 192, "tcp",
   "srmp", 193, "tcp",
   "irc", 194, "tcp",
   "dn6-nlm-aud", 195, "tcp",
   "dn6-smm-red", 196, "tcp",
   "dls", 197, "tcp",
   "dls-mon", 198, "tcp",
   "smux", 199, "tcp",
   "src", 200, "tcp",
   "at-rtmp", 201, "tcp",
   "at-nbp", 202, "tcp",
   "at-3", 203, "tcp",
   "at-echo", 204, "tcp",
   "at-5", 205, "tcp",
   "at-zis", 206, "tcp",
   "at-7", 207, "tcp",
   "at-8", 208, "tcp",
   "tam", 209, "tcp",
   "z39.50", 210, "tcp",
   "914c-g", 211, "tcp",
   "anet", 212, "tcp",
   "ipx", 213, "tcp",
   "vmpwscs", 214, "tcp",
   "softpc", 215, "tcp",
   "atls", 216, "tcp",
   "dbase", 217, "tcp",
   "mpp", 218, "tcp",
   "uarps", 219, "tcp",
   "imap3", 220, "tcp",
   "fln-spx", 221, "tcp",
   "rsh-spx", 222, "tcp",
   "cdc", 223, "tcp",
   "direct", 242, "tcp",
   "sur-meas", 243, "tcp",
   "dayna", 244, "tcp",
   "link", 245, "tcp",
   "dsp3270", 246, "tcp",
   "subntbcst_tftp", 247, "tcp",
   "bhfhs", 248, "tcp",
   "FW1-secureremote", 256, "tcp",
   "FW1-mc-fwmodule", 257, "tcp",
   "Fw1-mc-gui", 258, "tcp",
   "esro-gen", 259, "tcp",
   "openport", 260, "tcp",
   "nsiiops", 261, "tcp",
   "arcisdms", 262, "tcp",
   "hdap", 263, "tcp",
   "bgmp", 264, "tcp",
   "maybeFW1", 265, "tcp",
   "http-mgmt", 280, "tcp",
   "personal-link", 281, "tcp",
   "cableport-ax", 282, "tcp",
   "novastorbakcup", 308, "tcp",
   "entrusttime", 309, "tcp",
   "bhmds", 310, "tcp",
   "asip-webadmin", 311, "tcp",
   "vslmp", 312, "tcp",
   "magenta-logic", 313, "tcp",
   "opalis-robot", 314, "tcp",
   "dpsi", 315, "tcp",
   "decauth", 316, "tcp",
   "zannet", 317, "tcp",
   "pip", 321, "tcp",
   "pdap", 344, "tcp",
   "pawserv", 345, "tcp",
   "zserv", 346, "tcp",
   "fatserv", 347, "tcp",
   "csi-sgwp", 348, "tcp",
   "mftp", 349, "tcp",
   "matip-type-a", 350, "tcp",
   "matip-type-b", 351, "tcp",
   "dtag-ste-sb", 352, "tcp",
   "ndsauth", 353, "tcp",
   "bh611", 354, "tcp",
   "datex-asn", 355, "tcp",
   "cloanto-net-1", 356, "tcp",
   "bhevent", 357, "tcp",
   "shrinkwrap", 358, "tcp",
   "tenebris_nts", 359, "tcp",
   "scoi2odialog", 360, "tcp",
   "semantix", 361, "tcp",
   "srssend", 362, "tcp",
   "rsvp_tunnel", 363, "tcp",
   "aurora-cmgr", 364, "tcp",
   "dtk", 365, "tcp",
   "odmr", 366, "tcp",
   "mortgageware", 367, "tcp",
   "qbikgdp", 368, "tcp",
   "rpc2portmap", 369, "tcp",
   "codaauth2", 370, "tcp",
   "clearcase", 371, "tcp",
   "ulistserv", 372, "tcp",
   "legent-1", 373, "tcp",
   "legent-2", 374, "tcp",
   "hassle", 375, "tcp",
   "nip", 376, "tcp",
   "tnETOS", 377, "tcp",
   "dsETOS", 378, "tcp",
   "is99c", 379, "tcp",
   "is99s", 380, "tcp",
   "hp-collector", 381, "tcp",
   "hp-managed-node", 382, "tcp",
   "hp-alarm-mgr", 383, "tcp",
   "arns", 384, "tcp",
   "ibm-app", 385, "tcp",
   "asa", 386, "tcp",
   "aurp", 387, "tcp",
   "unidata-ldm", 388, "tcp",
   "ldap", 389, "tcp",
   "uis", 390, "tcp",
   "synotics-relay", 391, "tcp",
   "synotics-broker", 392, "tcp",
   "dis", 393, "tcp",
   "embl-ndt", 394, "tcp",
   "netcp", 395, "tcp",
   "netware-ip", 396, "tcp",
   "mptn", 397, "tcp",
   "kryptolan", 398, "tcp",
   "iso-tsap-c2", 399, "tcp",
   "work-sol", 400, "tcp",
   "ups", 401, "tcp",
   "genie", 402, "tcp",
   "decap", 403, "tcp",
   "nced", 404, "tcp",
   "ncld", 405, "tcp",
   "imsp", 406, "tcp",
   "timbuktu", 407, "tcp",
   "prm-sm", 408, "tcp",
   "prm-nm", 409, "tcp",
   "decladebug", 410, "tcp",
   "rmt", 411, "tcp",
   "synoptics-trap", 412, "tcp",
   "smsp", 413, "tcp",
   "infoseek", 414, "tcp",
   "bnet", 415, "tcp",
   "silverplatter", 416, "tcp",
   "onmux", 417, "tcp",
   "hyper-g", 418, "tcp",
   "ariel1", 419, "tcp",
   "smpte", 420, "tcp",
   "ariel2", 421, "tcp",
   "ariel3", 422, "tcp",
   "opc-job-start", 423, "tcp",
   "opc-job-track", 424, "tcp",
   "icad-el", 425, "tcp",
   "smartsdp", 426, "tcp",
   "svrloc", 427, "tcp",
   "ocs_cmu", 428, "tcp",
   "ocs_amu", 429, "tcp",
   "utmpsd", 430, "tcp",
   "utmpcd", 431, "tcp",
   "iasd", 432, "tcp",
   "nnsp", 433, "tcp",
   "mobileip-agent", 434, "tcp",
   "mobilip-mn", 435, "tcp",
   "dna-cml", 436, "tcp",
   "comscm", 437, "tcp",
   "dsfgw", 438, "tcp",
   "dasp", 439, "tcp",
   "sgcp", 440, "tcp",
   "decvms-sysmgt", 441, "tcp",
   "cvc_hostd", 442, "tcp",
   "https", 443, "tcp",
   "snpp", 444, "tcp",
   "microsoft-ds", 445, "tcp",
   "ddm-rdb", 446, "tcp",
   "ddm-dfm", 447, "tcp",
   "ddm-ssl", 448, "tcp",
   "as-servermap", 449, "tcp",
   "tserver", 450, "tcp",
   "sfs-smp-net", 451, "tcp",
   "sfs-config", 452, "tcp",
   "creativeserver", 453, "tcp",
   "contentserver", 454, "tcp",
   "creativepartnr", 455, "tcp",
   "macon-tcp", 456, "tcp",
   "scohelp", 457, "tcp",
   "appleqtc", 458, "tcp",
   "ampr-rcmd", 459, "tcp",
   "skronk", 460, "tcp",
   "datasurfsrv", 461, "tcp",
   "datasurfsrvsec", 462, "tcp",
   "alpes", 463, "tcp",
   "kpasswd5", 464, "tcp",
   "smtps", 465, "tcp",
   "digital-vrc", 466, "tcp",
   "mylex-mapd", 467, "tcp",
   "photuris", 468, "tcp",
   "rcp", 469, "tcp",
   "scx-proxy", 470, "tcp",
   "mondex", 471, "tcp",
   "ljk-login", 472, "tcp",
   "hybrid-pop", 473, "tcp",
   "tn-tl-w1", 474, "tcp",
   "tcpnethaspsrv", 475, "tcp",
   "tn-tl-fd1", 476, "tcp",
   "ss7ns", 477, "tcp",
   "spsc", 478, "tcp",
   "iafserver", 479, "tcp",
   "loadsrv", 480, "tcp",
   "dvs", 481, "tcp",
   "bgs-nsi", 482, "tcp",
   "ulpnet", 483, "tcp",
   "integra-sme", 484, "tcp",
   "powerburst", 485, "tcp",
   "sstats", 486, "tcp",
   "saft", 487, "tcp",
   "gss-http", 488, "tcp",
   "nest-protocol", 489, "tcp",
   "micom-pfs", 490, "tcp",
   "go-login", 491, "tcp",
   "ticf-1", 492, "tcp",
   "ticf-2", 493, "tcp",
   "pov-ray", 494, "tcp",
   "intecourier", 495, "tcp",
   "pim-rp-disc", 496, "tcp",
   "dantz", 497, "tcp",
   "siam", 498, "tcp",
   "iso-ill", 499, "tcp",
   "isakmp", 500, "tcp",
   "stmf", 501, "tcp",
   "asa-appl-proto", 502, "tcp",
   "intrinsa", 503, "tcp",
   "citadel", 504, "tcp",
   "mailbox-lm", 505, "tcp",
   "ohimsrv", 506, "tcp",
   "crs", 507, "tcp",
   "xvttp", 508, "tcp",
   "snare", 509, "tcp",
   "fcp", 510, "tcp",
   "passgo", 511, "tcp",
   "exec", 512, "tcp",
   "login", 513, "tcp",
   "shell", 514, "tcp",
   "printer", 515, "tcp",
   "videotex", 516, "tcp",
   "talk", 517, "tcp",
   "ntalk", 518, "tcp",
   "utime", 519, "tcp",
   "efs", 520, "tcp",
   "ripng", 521, "tcp",
   "ulp", 522, "tcp",
   "ibm-db2", 523, "tcp",
   "ncp", 524, "tcp",
   "timed", 525, "tcp",
   "tempo", 526, "tcp",
   "stx", 527, "tcp",
   "custix", 528, "tcp",
   "irc-serv", 529, "tcp",
   "courier", 530, "tcp",
   "conference", 531, "tcp",
   "netnews", 532, "tcp",
   "netwall", 533, "tcp",
   "mm-admin", 534, "tcp",
   "iiop", 535, "tcp",
   "opalis-rdv", 536, "tcp",
   "nmsp", 537, "tcp",
   "gdomap", 538, "tcp",
   "apertus-ldp", 539, "tcp",
   "uucp", 540, "tcp",
   "uucp-rlogin", 541, "tcp",
   "commerce", 542, "tcp",
   "klogin", 543, "tcp",
   "kshell", 544, "tcp",
   "ekshell", 545, "tcp",
   "dhcpv6-client", 546, "tcp",
   "dhcpv6-server", 547, "tcp",
   "afpovertcp", 548, "tcp",
   "idfp", 549, "tcp",
   "new-rwho", 550, "tcp",
   "cybercash", 551, "tcp",
   "deviceshare", 552, "tcp",
   "pirp", 553, "tcp",
   "rtsp", 554, "tcp",
   "dsf", 555, "tcp",
   "remotefs", 556, "tcp",
   "openvms-sysipc", 557, "tcp",
   "sdnskmp", 558, "tcp",
   "teedtap", 559, "tcp",
   "rmonitor", 560, "tcp",
   "monitor", 561, "tcp",
   "chshell", 562, "tcp",
   "snews", 563, "tcp",
   "9pfs", 564, "tcp",
   "whoami", 565, "tcp",
   "streettalk", 566, "tcp",
   "banyan-rpc", 567, "tcp",
   "ms-shuttle", 568, "tcp",
   "ms-rome", 569, "tcp",
   "meter", 570, "tcp",
   "umeter", 571, "tcp",
   "sonar", 572, "tcp",
   "banyan-vip", 573, "tcp",
   "ftp-agent", 574, "tcp",
   "vemmi", 575, "tcp",
   "ipcd", 576, "tcp",
   "vnas", 577, "tcp",
   "ipdd", 578, "tcp",
   "decbsrv", 579, "tcp",
   "sntp-heartbeat", 580, "tcp",
   "bdp", 581, "tcp",
   "scc-security", 582, "tcp",
   "philips-vc", 583, "tcp",
   "keyserver", 584, "tcp",
   "imap4-ssl", 585, "tcp",
   "password-chg", 586, "tcp",
   "submission", 587, "tcp",
   "cal", 588, "tcp",
   "eyelink", 589, "tcp",
   "tns-cml", 590, "tcp",
   "http-alt", 591, "tcp",
   "eudora-set", 592, "tcp",
   "http-rpc-epmap", 593, "tcp",
   "tpip", 594, "tcp",
   "cab-protocol", 595, "tcp",
   "smsd", 596, "tcp",
   "ptcnameservice", 597, "tcp",
   "sco-websrvrmg3", 598, "tcp",
   "acp", 599, "tcp",
   "ipcserver", 600, "tcp",
   "urm", 606, "tcp",
   "nqs", 607, "tcp",
   "sift-uft", 608, "tcp",
   "npmp-trap", 609, "tcp",
   "npmp-local", 610, "tcp",
   "npmp-gui", 611, "tcp",
   "qmqp", 628, "tcp",
   "ipp", 631, "tcp",
   "ginad", 634, "tcp",
   "ldapssl", 636, "tcp",
   "mac-srvr-admin", 660, "tcp",
   "doom", 666, "tcp",
   "lanserver", 637, "tcp",
   "resvc", 691, "tcp",
   "elcsd", 704, "tcp",
   "silc", 706, "tcp",
   "entrustmanager", 709, "tcp",
   "netviewdm1", 729, "tcp",
   "netviewdm2", 730, "tcp",
   "netviewdm3", 731, "tcp",
   "netcp", 740, "tcp",
   "netgw", 741, "tcp",
   "netrcs", 742, "tcp",
   "flexlm", 744, "tcp",
   "fujitsu-dev", 747, "tcp",
   "ris-cm", 748, "tcp",
   "kerberos-adm", 749, "tcp",
   "kerberos", 750, "tcp",
   "kerberos_master", 751, "tcp",
   "qrh", 752, "tcp",
   "rrh", 753, "tcp",
   "krb_prop", 754, "tcp",
   "nlogin", 758, "tcp",
   "con", 759, "tcp",
   "krbupdate", 760, "tcp",
   "kpasswd", 761, "tcp",
   "quotad", 762, "tcp",
   "cycleserv", 763, "tcp",
   "omserv", 764, "tcp",
   "webster", 765, "tcp",
   "phonebook", 767, "tcp",
   "vid", 769, "tcp",
   "cadlock", 770, "tcp",
   "rtip", 771, "tcp",
   "cycleserv2", 772, "tcp",
   "submit", 773, "tcp",
   "rpasswd", 774, "tcp",
   "entomb", 775, "tcp",
   "wpages", 776, "tcp",
   "wpgs", 780, "tcp",
   "hp-collector", 781, "tcp",
   "hp-managed-node", 782, "tcp",
   "hp-alarm-mgr", 783, "tcp",
   "concert", 786, "tcp",
   "controlit", 799, "tcp",
   "mdbs_daemon", 800, "tcp",
   "device", 801, "tcp",
   "supfilesrv", 871, "tcp",
   "rsync", 873, "tcp",
   "accessbuilder", 888, "tcp",
   "ftps-data", 989, "tcp",
   "samba-swat", 901, "tcp",
   "oftep-rpc", 950, "tcp",
   "rndc", 953, "tcp",
   "securenetpro-sensor", 975, "tcp",
   "ftps", 990, "tcp",
   "telnets", 992, "tcp",
   "imaps", 993, "tcp",
   "ircs", 994, "tcp",
   "pop3s", 995, "tcp",
   "xtreelic", 996, "tcp",
   "maitrd", 997, "tcp",
   "busboy", 998, "tcp",
   "garcon", 999, "tcp",
   "cadlock", 1000, "tcp",
   "ufsd", 1008, "tcp",
   "kdm", 1024, "tcp",
   "NFS-or-IIS", 1025, "tcp",
   "LSA-or-nterm", 1026, "tcp",
   "IIS", 1027, "tcp",
   "ms-lsa", 1029, "tcp",
   "iad1", 1030, "tcp",
   "iad2", 1031, "tcp",
   "iad3", 1032, "tcp",
   "netinfo", 1033, "tcp",
   "java-or-OTGfileshare", 1050, "tcp",
   "nim", 1058, "tcp",
   "nimreg", 1059, "tcp",
   "instl_boots", 1067, "tcp",
   "instl_bootc", 1068, "tcp",
   "socks", 1080, "tcp",
   "ansoft-lm-1", 1083, "tcp",
   "ansoft-lm-2", 1084, "tcp",
   "xaudio", 1103, "tcp",
   "kpop", 1109, "tcp",
   "nfsd-status", 1110, "tcp",
   "msql", 1112, "tcp",
   "supfiledbg", 1127, "tcp",
   "cce3x", 1139, "tcp",
   "nfa", 1155, "tcp",
   "skkserv", 1178, "tcp",
   "lupa", 1212, "tcp",
   "nerv", 1222, "tcp",
   "hotline", 1234, "tcp",
   "msg", 1241, "tcp",
   "hermes", 1248, "tcp",
   "alta-ana-lm", 1346, "tcp",
   "bbn-mmc", 1347, "tcp",
   "bbn-mmx", 1348, "tcp",
   "sbook", 1349, "tcp",
   "editbench", 1350, "tcp",
   "equationbuilder", 1351, "tcp",
   "lotusnotes", 1352, "tcp",
   "relief", 1353, "tcp",
   "rightbrain", 1354, "tcp",
   "intuitive-edge", 1355, "tcp",
   "cuillamartin", 1356, "tcp",
   "pegboard", 1357, "tcp",
   "connlcli", 1358, "tcp",
   "ftsrv", 1359, "tcp",
   "mimer", 1360, "tcp",
   "linx", 1361, "tcp",
   "timeflies", 1362, "tcp",
   "ndm-requester", 1363, "tcp",
   "ndm-server", 1364, "tcp",
   "adapt-sna", 1365, "tcp",
   "netware-csp", 1366, "tcp",
   "dcs", 1367, "tcp",
   "screencast", 1368, "tcp",
   "gv-us", 1369, "tcp",
   "us-gv", 1370, "tcp",
   "fc-cli", 1371, "tcp",
   "fc-ser", 1372, "tcp",
   "chromagrafx", 1373, "tcp",
   "molly", 1374, "tcp",
   "bytex", 1375, "tcp",
   "ibm-pps", 1376, "tcp",
   "cichlid", 1377, "tcp",
   "elan", 1378, "tcp",
   "dbreporter", 1379, "tcp",
   "telesis-licman", 1380, "tcp",
   "apple-licman", 1381, "tcp",
   "gwha", 1383, "tcp",
   "os-licman", 1384, "tcp",
   "atex_elmd", 1385, "tcp",
   "checksum", 1386, "tcp",
   "cadsi-lm", 1387, "tcp",
   "objective-dbc", 1388, "tcp",
   "iclpv-dm", 1389, "tcp",
   "iclpv-sc", 1390, "tcp",
   "iclpv-sas", 1391, "tcp",
   "iclpv-pm", 1392, "tcp",
   "iclpv-nls", 1393, "tcp",
   "iclpv-nlc", 1394, "tcp",
   "iclpv-wsm", 1395, "tcp",
   "dvl-activemail", 1396, "tcp",
   "audio-activmail", 1397, "tcp",
   "video-activmail", 1398, "tcp",
   "cadkey-licman", 1399, "tcp",
   "cadkey-tablet", 1400, "tcp",
   "goldleaf-licman", 1401, "tcp",
   "prm-sm-np", 1402, "tcp",
   "prm-nm-np", 1403, "tcp",
   "igi-lm", 1404, "tcp",
   "ibm-res", 1405, "tcp",
   "netlabs-lm", 1406, "tcp",
   "dbsa-lm", 1407, "tcp",
   "sophia-lm", 1408, "tcp",
   "here-lm", 1409, "tcp",
   "hiq", 1410, "tcp",
   "af", 1411, "tcp",
   "innosys", 1412, "tcp",
   "innosys-acl", 1413, "tcp",
   "ibm-mqseries", 1414, "tcp",
   "dbstar", 1415, "tcp",
   "novell-lu6.2", 1416, "tcp",
   "timbuktu-srv1", 1417, "tcp",
   "timbuktu-srv2", 1418, "tcp",
   "timbuktu-srv3", 1419, "tcp",
   "timbuktu-srv4", 1420, "tcp",
   "gandalf-lm", 1421, "tcp",
   "autodesk-lm", 1422, "tcp",
   "essbase", 1423, "tcp",
   "hybrid", 1424, "tcp",
   "zion-lm", 1425, "tcp",
   "sas-1", 1426, "tcp",
   "mloadd", 1427, "tcp",
   "informatik-lm", 1428, "tcp",
   "nms", 1429, "tcp",
   "tpdu", 1430, "tcp",
   "rgtp", 1431, "tcp",
   "blueberry-lm", 1432, "tcp",
   "ms-sql-s", 1433, "tcp",
   "ms-sql-m", 1434, "tcp",
   "ibm-cics", 1435, "tcp",
   "sas-2", 1436, "tcp",
   "tabula", 1437, "tcp",
   "eicon-server", 1438, "tcp",
   "eicon-x25", 1439, "tcp",
   "eicon-slp", 1440, "tcp",
   "cadis-1", 1441, "tcp",
   "cadis-2", 1442, "tcp",
   "ies-lm", 1443, "tcp",
   "marcam-lm", 1444, "tcp",
   "proxima-lm", 1445, "tcp",
   "ora-lm", 1446, "tcp",
   "apri-lm", 1447, "tcp",
   "oc-lm", 1448, "tcp",
   "peport", 1449, "tcp",
   "dwf", 1450, "tcp",
   "infoman", 1451, "tcp",
   "gtegsc-lm", 1452, "tcp",
   "genie-lm", 1453, "tcp",
   "interhdl_elmd", 1454, "tcp",
   "esl-lm", 1455, "tcp",
   "dca", 1456, "tcp",
   "valisys-lm", 1457, "tcp",
   "nrcabq-lm", 1458, "tcp",
   "proshare1", 1459, "tcp",
   "proshare2", 1460, "tcp",
   "ibm_wrless_lan", 1461, "tcp",
   "world-lm", 1462, "tcp",
   "nucleus", 1463, "tcp",
   "msl_lmd", 1464, "tcp",
   "pipes", 1465, "tcp",
   "oceansoft-lm", 1466, "tcp",
   "csdmbase", 1467, "tcp",
   "csdm", 1468, "tcp",
   "aal-lm", 1469, "tcp",
   "uaiact", 1470, "tcp",
   "csdmbase", 1471, "tcp",
   "csdm", 1472, "tcp",
   "openmath", 1473, "tcp",
   "telefinder", 1474, "tcp",
   "taligent-lm", 1475, "tcp",
   "clvm-cfg", 1476, "tcp",
   "ms-sna-server", 1477, "tcp",
   "ms-sna-base", 1478, "tcp",
   "dberegister", 1479, "tcp",
   "pacerforum", 1480, "tcp",
   "airs", 1481, "tcp",
   "miteksys-lm", 1482, "tcp",
   "afs", 1483, "tcp",
   "confluent", 1484, "tcp",
   "lansource", 1485, "tcp",
   "nms_topo_serv", 1486, "tcp",
   "localinfosrvr", 1487, "tcp",
   "docstor", 1488, "tcp",
   "dmdocbroker", 1489, "tcp",
   "insitu-conf", 1490, "tcp",
   "anynetgateway", 1491, "tcp",
   "stone-design-1", 1492, "tcp",
   "netmap_lm", 1493, "tcp",
   "citrix-ica", 1494, "tcp",
   "cvc", 1495, "tcp",
   "liberty-lm", 1496, "tcp",
   "rfx-lm", 1497, "tcp",
   "watcom-sql", 1498, "tcp",
   "fhc", 1499, "tcp",
   "vlsi-lm", 1500, "tcp",
   "sas-3", 1501, "tcp",
   "shivadiscovery", 1502, "tcp",
   "imtc-mcs", 1503, "tcp",
   "evb-elm", 1504, "tcp",
   "funkproxy", 1505, "tcp",
   "utcd", 1506, "tcp",
   "symplex", 1507, "tcp",
   "diagmond", 1508, "tcp",
   "robcad-lm", 1509, "tcp",
   "mvx-lm", 1510, "tcp",
   "3l-l1", 1511, "tcp",
   "wins", 1512, "tcp",
   "fujitsu-dtc", 1513, "tcp",
   "fujitsu-dtcns", 1514, "tcp",
   "ifor-protocol", 1515, "tcp",
   "vpad", 1516, "tcp",
   "vpac", 1517, "tcp",
   "vpvd", 1518, "tcp",
   "vpvc", 1519, "tcp",
   "atm-zip-office", 1520, "tcp",
   "oracle", 1521, "tcp",
   "rna-lm", 1522, "tcp",
   "cichild-lm", 1523, "tcp",
   "ingreslock", 1524, "tcp",
   "orasrv", 1525, "tcp",
   "pdap-np", 1526, "tcp",
   "tlisrv", 1527, "tcp",
   "mciautoreg", 1528, "tcp",
   "support", 1529, "tcp",
   "rap-service", 1530, "tcp",
   "rap-listen", 1531, "tcp",
   "miroconnect", 1532, "tcp",
   "virtual-places", 1533, "tcp",
   "micromuse-lm", 1534, "tcp",
   "ampr-info", 1535, "tcp",
   "ampr-inter", 1536, "tcp",
   "sdsc-lm", 1537, "tcp",
   "3ds-lm", 1538, "tcp",
   "intellistor-lm", 1539, "tcp",
   "rds", 1540, "tcp",
   "rds2", 1541, "tcp",
   "gridgen-elmd", 1542, "tcp",
   "simba-cs", 1543, "tcp",
   "aspeclmd", 1544, "tcp",
   "vistium-share", 1545, "tcp",
   "abbaccuray", 1546, "tcp",
   "laplink", 1547, "tcp",
   "axon-lm", 1548, "tcp",
   "shivahose", 1549, "tcp",
   "3m-image-lm", 1550, "tcp",
   "hecmtl-db", 1551, "tcp",
   "pciarray", 1552, "tcp",
   "issd", 1600, "tcp",
   "nkd", 1650, "tcp",
   "shiva_confsrvr", 1651, "tcp",
   "xnmp", 1652, "tcp",
   "netview-aix-1", 1661, "tcp",
   "netview-aix-2", 1662, "tcp",
   "netview-aix-3", 1663, "tcp",
   "netview-aix-4", 1664, "tcp",
   "netview-aix-5", 1665, "tcp",
   "netview-aix-6", 1666, "tcp",
   "netview-aix-7", 1667, "tcp",
   "netview-aix-8", 1668, "tcp",
   "netview-aix-9", 1669, "tcp",
   "netview-aix-10", 1670, "tcp",
   "netview-aix-11", 1671, "tcp",
   "netview-aix-12", 1672, "tcp",
   "CarbonCopy", 1680, "tcp",
   "H.323/Q.931", 1720, "tcp",
   "pptp", 1723, "tcp",
   "pcm", 1827, "tcp",
   "UPnP", 1900, "tcp",
   "licensedaemon", 1986, "tcp",
   "tr-rsrb-p1", 1987, "tcp",
   "tr-rsrb-p2", 1988, "tcp",
   "tr-rsrb-p3", 1989, "tcp",
   "stun-p1", 1990, "tcp",
   "stun-p2", 1991, "tcp",
   "stun-p3", 1992, "tcp",
   "snmp-tcp-port", 1993, "tcp",
   "stun-port", 1994, "tcp",
   "perf-port", 1995, "tcp",
   "tr-rsrb-port", 1996, "tcp",
   "gdp-port", 1997, "tcp",
   "x25-svc-port", 1998, "tcp",
   "tcp-id-port", 1999, "tcp",
   "callbook", 2000, "tcp",
   "dc", 2001, "tcp",
   "globe", 2002, "tcp",
   "cfingerd", 2003, "tcp",
   "mailbox", 2004, "tcp",
   "deslogin", 2005, "tcp",
   "invokator", 2006, "tcp",
   "dectalk", 2007, "tcp",
   "conf", 2008, "tcp",
   "news", 2009, "tcp",
   "search", 2010, "tcp",
   "raid-cc", 2011, "tcp",
   "ttyinfo", 2012, "tcp",
   "raid-am", 2013, "tcp",
   "troff", 2014, "tcp",
   "cypress", 2015, "tcp",
   "bootserver", 2016, "tcp",
   "cypress-stat", 2017, "tcp",
   "terminaldb", 2018, "tcp",
   "whosockami", 2019, "tcp",
   "xinupageserver", 2020, "tcp",
   "servexec", 2021, "tcp",
   "down", 2022, "tcp",
   "xinuexpansion3", 2023, "tcp",
   "xinuexpansion4", 2024, "tcp",
   "ellpack", 2025, "tcp",
   "scrabble", 2026, "tcp",
   "shadowserver", 2027, "tcp",
   "submitserver", 2028, "tcp",
   "device2", 2030, "tcp",
   "blackboard", 2032, "tcp",
   "glogger", 2033, "tcp",
   "scoremgr", 2034, "tcp",
   "imsldoc", 2035, "tcp",
   "objectmanager", 2038, "tcp",
   "lam", 2040, "tcp",
   "interbase", 2041, "tcp",
   "isis", 2042, "tcp",
   "isis-bcast", 2043, "tcp",
   "rimsl", 2044, "tcp",
   "cdfunc", 2045, "tcp",
   "sdfunc", 2046, "tcp",
   "dls", 2047, "tcp",
   "dls-monitor", 2048, "tcp",
   "nfs", 2049, "tcp",
   "distrib-net-losers", 2064, "tcp",
   "knetd", 2053, "tcp",
   "dlsrpn", 2065, "tcp",
   "dlswpn", 2067, "tcp",
   "eklogin", 2105, "tcp",
   "ekshell", 2106, "tcp",
   "rkinit", 2108, "tcp",
   "kx", 2111, "tcp",
   "kip", 2112, "tcp",
   "kauth", 2120, "tcp",
   "ats", 2201, "tcp",
   "ivs-video", 2232, "tcp",
   "ivsd", 2241, "tcp",
   "compaqdiag", 2301, "tcp",
   "pehelp", 2307, "tcp",
   "cvspserver", 2401, "tcp",
   "venus", 2430, "tcp",
   "venus-se", 2431, "tcp",
   "codasrv", 2432, "tcp",
   "codasrv-se", 2433, "tcp",
   "rtsserv", 2500, "tcp",
   "rtsclient", 2501, "tcp",
   "hp-3000-telnet", 2564, "tcp",
   "zebrasrv", 2600, "tcp",
   "zebra", 2601, "tcp",
   "ripd", 2602, "tcp",
   "ripngd", 2603, "tcp",
   "ospfd", 2604, "tcp",
   "bgpd", 2605, "tcp",
   "webster", 2627, "tcp",
   "sybase", 2638, "tcp",
   "listen", 2766, "tcp",
   "www-dev", 2784, "tcp",
   "iss-realsec", 2998, "tcp",
   "ppp", 3000, "tcp",
   "nessusd", 3001, "tcp",
   "deslogin", 3005, "tcp",
   "deslogind", 3006, "tcp",
   "cfs", 3049, "tcp",
   "PowerChute", 3052, "tcp",
   "distrib-net-proxy", 3064, "tcp",
   "sj3", 3086, "tcp",
   "squid-http", 3128, "tcp",
   "vmodem", 3141, "tcp",
   "ccmail", 3264, "tcp",
   "globalcatLDAP", 3268, "tcp",
   "globalcatLDAPssl", 3269, "tcp",
   "mysql", 3306, "tcp",
   "dec-notes", 3333, "tcp",
   "msdtc", 3372, "tcp",
   "ms-term-serv", 3389, "tcp",
   "bmap", 3421, "tcp",
   "prsvp", 3455, "tcp",
   "vat", 3456, "tcp",
   "vat-control", 3457, "tcp",
   "track", 3462, "tcp",
   "udt_os", 3900, "tcp",
   "mapper-nodemgr", 3984, "tcp",
   "mapper-mapethd", 3985, "tcp",
   "mapper-ws_ethd", 3986, "tcp",
   "remoteanything", 3999, "tcp",
   "remoteanything", 4000, "tcp",
   "netcheque", 4008, "tcp",
   "lockd", 4045, "tcp",
   "nuts_dem", 4132, "tcp",
   "nuts_bootp", 4133, "tcp",
   "wincim", 4144, "tcp",
   "rwhois", 4321, "tcp",
   "msql", 4333, "tcp",
   "unicall", 4343, "tcp",
   "krb524", 4444, "tcp",
   "proxy-plus", 4480, "tcp",
   "sae-urn", 4500, "tcp",
   "fax", 4557, "tcp",
   "hylafax", 4559, "tcp",
   "rfa", 4672, "tcp",
   "maybeveritas", 4987, "tcp",
   "maybeveritas", 4998, "tcp",
   "UPnP", 5000, "tcp",
   "commplex-link", 5001, "tcp",
   "rfe", 5002, "tcp",
   "telelpathstart", 5010, "tcp",
   "telelpathattack", 5011, "tcp",
   "mmcc", 5050, "tcp",
   "rmonitor_secure", 5145, "tcp",
   "aol", 5190, "tcp",
   "aol-1", 5191, "tcp",
   "aol-2", 5192, "tcp",
   "aol-3", 5193, "tcp",
   "sgi-dgl", 5232, "tcp",
   "padl2sim", 5236, "tcp",
   "hacl-hb", 5300, "tcp",
   "hacl-gs", 5301, "tcp",
   "hacl-cfg", 5302, "tcp",
   "hacl-probe", 5303, "tcp",
   "hacl-local", 5304, "tcp",
   "hacl-test", 5305, "tcp",
   "cfengine", 5308, "tcp",
   "pcduo-old", 5400, "tcp",
   "pcduo", 5405, "tcp",
   "postgres", 5432, "tcp",
   "secureidprop", 5510, "tcp",
   "sdlog", 5520, "tcp",
   "sdserv", 5530, "tcp",
   "sdreport", 5540, "tcp",
   "sdadmind", 5550, "tcp",
   "freeciv", 5555, "tcp",
   "pcanywheredata", 5631, "tcp",
   "pcanywherestat", 5632, "tcp",
   "canna", 5680, "tcp",
   "proshareaudio", 5713, "tcp",
   "prosharevideo", 5714, "tcp",
   "prosharedata", 5715, "tcp",
   "prosharerequest", 5716, "tcp",
   "prosharenotify", 5717, "tcp",
   "vnc-http", 5800, "tcp",
   "vnc-http-1", 5801, "tcp",
   "vnc-http-2", 5802, "tcp",
   "vnc-http-3", 5803, "tcp",
   "vnc", 5900, "tcp",
   "vnc-1", 5901, "tcp",
   "vnc-2", 5902, "tcp",
   "vnc-3", 5903, "tcp",
   "ncd-pref-tcp", 5977, "tcp",
   "ncd-diag-tcp", 5978, "tcp",
   "ncd-conf-tcp", 5979, "tcp",
   "ncd-pref", 5997, "tcp",
   "ncd-diag", 5998, "tcp",
   "ncd-conf", 5999, "tcp",
   "X11", 6000, "tcp",
   "X11:1", 6001, "tcp",
   "X11:2", 6002, "tcp",
   "X11:3", 6003, "tcp",
   "X11:4", 6004, "tcp",
   "X11:5", 6005, "tcp",
   "X11:6", 6006, "tcp",
   "X11:7", 6007, "tcp",
   "X11:8", 6008, "tcp",
   "X11:9", 6009, "tcp",
   "arcserve", 6050, "tcp",
   "VeritasBackupExec", 6101, "tcp",
   "RETS-or-BackupExec", 6103, "tcp",
   "isdninfo", 6105, "tcp",
   "isdninfo", 6106, "tcp",
   "softcm", 6110, "tcp",
   "spc", 6111, "tcp",
   "dtspc", 6112, "tcp",
   "meta-corp", 6141, "tcp",
   "aspentec-lm", 6142, "tcp",
   "watershed-lm", 6143, "tcp",
   "statsci1-lm", 6144, "tcp",
   "statsci2-lm", 6145, "tcp",
   "lonewolf-lm", 6146, "tcp",
   "montage-lm", 6147, "tcp",
   "ricardo-lm", 6148, "tcp",
   "gnutella", 6346, "tcp",
   "PowerChutePLUS", 6547, "tcp",
   "PowerChutePLUS", 6548, "tcp",
   "netop-rc", 6502, "tcp",
   "xdsxdm", 6558, "tcp",
   "analogx", 6588, "tcp",
   "irc-serv", 6666, "tcp",
   "irc", 6667, "tcp",
   "irc", 6668, "tcp",
   "acmsoda", 6969, "tcp",
   "napster", 6699, "tcp",
   "afs3-fileserver", 7000, "tcp",
   "afs3-callback", 7001, "tcp",
   "afs3-prserver", 7002, "tcp",
   "afs3-vlserver", 7003, "tcp",
   "afs3-kaserver", 7004, "tcp",
   "afs3-volser", 7005, "tcp",
   "afs3-errors", 7006, "tcp",
   "afs3-bos", 7007, "tcp",
   "afs3-update", 7008, "tcp",
   "afs3-rmtsys", 7009, "tcp",
   "ups-onlinet", 7010, "tcp",
   "realserver", 7070, "tcp",
   "font-service", 7100, "tcp",
   "fodms", 7200, "tcp",
   "dlip", 7201, "tcp",
   "icb", 7326, "tcp",
   "qaz", 7597, "tcp",
   "ajp12", 8007, "tcp",
   "ajp13", 8009, "tcp",
   "http-proxy", 8080, "tcp",
   "blackice-icecap", 8081, "tcp",
   "blackice-alerts", 8082, "tcp",
   "sun-answerbook", 8888, "tcp",
   "seosload", 8892, "tcp",
   "zeus-admin", 9090, "tcp",
   "jetdirect", 9100, "tcp",
   "DragonIDSConsole", 9111, "tcp",
   "ms-sql2000", 9152, "tcp",
   "man", 9535, "tcp",
   "sd", 9876, "tcp",
   "issa", 9991, "tcp",
   "issc", 9992, "tcp",
   "snet-sensor-mgmt", 10000, "tcp",
   "stel", 10005, "tcp",
   "amandaidx", 10082, "tcp",
   "amidxtape", 10083, "tcp",
   "pksd", 11371, "tcp",
   "cce4x", 12000, "tcp",
   "NetBus", 12345, "tcp",
   "NetBus", 12346, "tcp",
   "VeritasNetbackup", 13701, "tcp",
   "VeritasNetbackup", 13702, "tcp",
   "VeritasNetbackup", 13705, "tcp",
   "VeritasNetbackup", 13706, "tcp",
   "VeritasNetbackup", 13708, "tcp",
   "VeritasNetbackup", 13709, "tcp",
   "VeritasNetbackup", 13710, "tcp",
   "VeritasNetbackup", 13711, "tcp",
   "VeritasNetbackup", 13712, "tcp",
   "VeritasNetbackup", 13713, "tcp",
   "VeritasNetbackup", 13714, "tcp",
   "VeritasNetbackup", 13715, "tcp",
   "VeritasNetbackup", 13716, "tcp",
   "VeritasNetbackup", 13717, "tcp",
   "VeritasNetbackup", 13718, "tcp",
   "VeritasNetbackup", 13720, "tcp",
   "VeritasNetbackup", 13721, "tcp",
   "VeritasNetbackup", 13722, "tcp",
   "VeritasNetbackup", 13782, "tcp",
   "VeritasNetbackup", 13783, "tcp",
   "subseven", 16959, "tcp",
   "isode-dua", 17007, "tcp",
   "biimenu", 18000, "tcp",
   "btx", 20005, "tcp",
   "wnn6", 22273, "tcp",
   "wnn6_Cn", 22289, "tcp",
   "wnn6_Kr", 22305, "tcp",
   "wnn6_Tw", 22321, "tcp",
   "hpnpd", 22370, "tcp",
   "wnn6_DS", 26208, "tcp",
   "subseven", 27374, "tcp",
   "Trinoo_Master", 27665, "tcp",
   "Elite", 31337, "tcp",
   "sometimes-rpc3", 32770, "tcp",
   "sometimes-rpc5", 32771, "tcp",
   "sometimes-rpc7", 32772, "tcp",
   "sometimes-rpc9", 32773, "tcp",
   "sometimes-rpc11", 32774, "tcp",
   "sometimes-rpc13", 32775, "tcp",
   "sometimes-rpc15", 32776, "tcp",
   "sometimes-rpc17", 32777, "tcp",
   "sometimes-rpc19", 32778, "tcp",
   "sometimes-rpc21", 32779, "tcp",
   "sometimes-rpc23", 32780, "tcp",
   "sometimes-rpc25", 32786, "tcp",
   "sometimes-rpc27", 32787, "tcp",
   "reachout", 43188, "tcp",
   "coldfusion-auth", 44442, "tcp",
   "coldfusion-auth", 44443, "tcp",
   "dbbrowse", 47557, "tcp",
   "compaqdiag", 49400, "tcp",
   "bo2k", 54320, "tcp",
   "netprowler-manager", 61439, "tcp",
   "netprowler-manager2", 61440, "tcp",
   "netprowler-sensor", 61441, "tcp",
   "pcanywhere", 65301, "tcp",
};
#endif