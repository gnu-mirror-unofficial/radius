#! /usr/bin/perl
# This file is part of GNU RADIUS.
# Copyright (C) 2001, 2007 Oswaldo E. Aguirre M., Francisco J. Obispo S.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or   
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the  
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# 

use CGI;
use CGI::Carp qw(fatalsToBrowser);
use DBI;



#
# Permite mostrar la informacion que se encuentra en la base de datos de radius
#


my $q=new CGI;


my @fields;
my @fieldsdb;
my %fieldslabels;

# User to access  MYSQL
$mysql_login='radius';
$mysql_pass='radius-password';
$mysql_table='calls';

# You probably don't want to modify this unless your
# database is on another host.
# In that case use 
# $mysql_dsn = "DBI:mysql:database=radius;host=myhost.domain.com;port=<port-no>";
$mysql_dsn = "DBI:mysql:database=RADIUS;";

#Colors for the table rows
$color1="#DDDDDD";
$color2="#FFFFDD";
#
# Set to 1 if you wish to see the SQL queries in you error_log
my $DEBUG=0;

# Some variables that you can customize to fit your needs

# Month Names
my @mesesNom=("Enero","Febrero","Marzo","Abril","Mayo","Junio","Julio","Agosto","Septiembre","Octubre","Noviembre","Diciembre");


# Modify this to suit your language..

my %lang=(
	  "Title" => "GNU Radius WEB-RADACT",
	  "Date-Range" => "Rango de Fechas",
	  "From" => "Desde",
	  "To" => "Hasta",
          "Page" => "Pagina",
	  "This" => "Misma",
          "Next" => "Sigiente",
          "Prev" => "Precedente",
	  "records" => "entradas",
	  "Time" => "Hora",
	  "User" => "Usuario",
	  "Show-Info" => "Mostrar",
          "Limit" => "Limite",
	  "All" => "Todos",
	  "Unknown" => "Desconocido",
	  "date not selected" => "Error: Debe escoger el Rango de Fecha / Hora",
	  
	  );

# These define MySQL table field semantics.
my %field_sem=(
	  "Event_ID" => "status",
	  "Connect_Term_Reason" => "Reason_Discon",
	  "Acct_Session_Time" => "acct_session_time"
);	       

# You shouldn't modify beyond this point unless you
# know what you're doing  
my $res;
my $fecha;
my $fecha_end;
my $sth;

my %Cisco_Disconnect_Cause=(
			    "2" =>  "Unknown",
			    "4" =>  "CLID-Authentication-Failure",
			    "10" =>  "No-Carrier",
			    "11" =>  "Lost-Carrier",
			    "12" =>  "No-Detected-Result-Codes",
			    "20" =>  "User-Ends-Session",
			    "21" =>  "Idle-Timeout",
			    "22" =>  "Exit-Telnet-Session",
			    "23" =>  "No-Remote-IP-Addr",
			    "24" =>  "Exit-Raw-TCP",
			    "25" =>  "Password-Fail",
			    "26" =>  "Raw-TCP-Disabled",
			    "27" =>  "Control-C-Detected",
			    "28" =>  "EXEC-Program-Destroyed",
			    "40" =>  "Timeout-PPP-LCP",
			    "41" =>  "Failed-PPP-LCP-Negotiation",
			    "42" =>  "Failed-PPP-PAP-Auth-Fail",
			    "43" =>  "Failed-PPP-CHAP-Auth",
			    "44" =>  "Failed-PPP-Remote-Auth",
			    "45" =>  "PPP-Remote-Terminate",
			    "46" =>  "PPP-Closed-Event",
			    "100" =>  "Session-Timeout",
			    "101" =>  "Session-Failed-Security",
			    "102" =>  "Session-End-Callback",
			    "120" =>  "Invalid-Protocol"
			    );


my $dbh=DBI->connect($mysql_dsn,$mysql_login,$mysql_pass) || die ("Conectando: " . DBI->errstr);

my $sql="SELECT var,title FROM calls_title ";

warn($sql) if($DEBUG == 1);

$sth=$dbh->prepare($sql) || die ("Error Preparing: " . $sql . " - " . $dbh->errstr);
$sth->execute || die("Executing: " . $sql . " - "  . $dbh->errstr);
while(my $arr=$sth->fetchrow_arrayref){
    push @fieldsdb,$$arr[0];
    $fieldslabels{$$arr[0]}=$$arr[1];
}
$sth->finish;

@fields=(!$q->param("view")) ? @fieldsdb : $q->param("view");

if ($q->param("idia") ne $lang{"All"} && 
    $q->param("imes") ne $lang{"All"} && 
    $q->param("iano") ne $lang{"All"} && 
    $q->param("fdia") ne $lang{"All"} && 
    $q->param("fmes") ne $lang{"All"} && 
    $q->param("fano") ne $lang{"All"}) {
         $ifecha=$q->param("iano") . "-" . $q->param("imes") . "-" . $q->param("idia");
         $ifecha.=" " . $q->param("ihora");	
         $ffecha=$q->param("fano") . "-" . $q->param("fmes") . "-" . $q->param("fdia");
         $ffecha.=" " . $q->param("fhora");
}

my $logs="SELECT ";
my $select=join(',',@fields);
$logs.= $select ;
$logs.=" FROM " . $mysql_table;

if ($ifecha && $ffecha){
    $logs.=" WHERE Event_Date_Time > '" . $ifecha . "' AND Event_Date_Time < '" . $ffecha . "' "; 
}

elsif (($ifecha && !$ffecha) || (!$ifecha && $ffecha) ){
    $res.="<font color='#FF0000'>$lang{'date not selected'}</font>";
}
$logs.=" AND user_name LIKE '" . $q->param("usuario") . "'" if($q->param("usuario"));

$logs.=" ORDER BY " . $q->param("order") if($q->param("order"));

$limit = $q->param("limite"); 
$limit = 25 if (!$limit);

if ($logs ne $q->param("last-query")) {
	$init = 1;
	$offset = 0;
	warn('INITING') if($DEBUG == 1);
} else {
	$offset = $q->param("offset");
}	

sub increment() {
    if ($q->param('pagina') eq 'Next') {
        return $limit;
    } elsif ($q->param('pagina') eq 'Prev') {
        return -$limit;
    }
    return 0;
}

$old_query = $logs;

if (!$init && ($q->param('pagina') ne $q->param('last-cmd'))) {
    if ($q->param('last-cmd') ne 'This') {
        $offset += 2*increment();
    } else {
        $offset += increment();
    }
}

$logs .= " LIMIT ";
$logs .= $offset . "," if ($offset);
$logs .= $limit;
warn($logs) if($DEBUG == 10);

if (!$init) {
	$offset += increment();
} elsif ($q->param('pagina') ne 'This') {
	$offset = $limit;
}

warn($logs) if($DEBUG == 1);
$res.="<table border=0 width='100%' align='center'><tr><td>";
$res.=$q->start_form(-action=>'radact.cgi',-method=>'post');
$res .= $q->hidden(-name=>'last-query',-default=>$old_query,-override=>1);
$res .= $q->hidden(-name=>'last-cmd',-default=>$q->param('pagina'),-override=>1);
# Fecha
my $sqlfecha="SELECT DISTINCT DATE_FORMAT(Event_Date_Time,'%e'),DATE_FORMAT(Event_Date_Time,'%m'),DATE_FORMAT(Event_Date_Time,'%Y') FROM " . $mysql_table . " ORDER BY Event_Date_Time";

$sth=$dbh->prepare($sqlfecha) || die ("Error Preparing: $sqlfecha -" . $dbh->errstr);
$sth->execute || die ("Error Executing: $sqlfecha -" . $dbh->errstr);
my($dia,$mes,$ano);
my($pdia,$pmes,$pano);
my (@dias,@meses,@anos);

my %mesesval;
while (my $arr=$sth->fetchrow_arrayref) {
    ($dia,$mes,$ano)=@$arr;
    push @dias,$dia if($dia ne $pdia);
    if($mes ne $pmes){
	push @meses,$mes;
	$mesesval{$mes}=$mesesNom[$mes - 1];
    }
    push @anos,$ano if($ano ne $pano);
    $pdia=$dia;
    $pmes=$mes;
    $pano=$ano;
}

$sth->finish;

push @dias,$lang{"All"};
push @meses,$lang{"All"};
push @anos,$lang{"All"};

$res.="<br><b>" . $lang{"Date-Range"}  . "</b><br> ";

$res.=$lang{"From"} . ": " . $q->popup_menu(-name=>'idia',-values=>\@dias);
$res.="-" . $q->popup_menu(-name=>'imes',-values=>\@meses,-labels=>\%mesesval);
$res.="-" . $q->popup_menu(-name=>'iano',-values=>\@anos);
$res.="<br>";
$res.=$lang{"To"} . ": " . $q->popup_menu(-name=>'fdia',-values=>\@dias);
$res.="-" . $q->popup_menu(-name=>'fmes',-values=>\@meses,-labels=>\%mesesval);
$res.="-" . $q->popup_menu(-name=>'fano',-values=>\@anos);


$res.="<br><b>" . $lang{"Time"} . "</b><br>" . $lang{"From"} . ": " . $q->textfield(-name=>'ihora',-size=>8,-value=>'00:00:00') . $lang{"To"} . ": " . $q->textfield(-name=>'fhora',-size=>8,-value=>'23:59:59') . " (HH:MM:SS) " ;
$res.="<br>" . $lang{"User"} . ": " . $q->textfield(-name=>'usuario',-size=>20) . "<br>";
$res.="</td><td>";
$res.=$q->checkbox_group(-name=>'view',-values=>\@fieldsdb,-default=>\@fields,-labels=>\%fieldslabels,-columns=>"3");
$res.="</td></tr></table>";

my @valores=('This','Next','Prev');
my %labels=('This' => $lang{"This"}, 'Next'=>$lang{"Next"},
         'Prev'=>$lang{"Prev"});

$res .= "<hr>" . $lang{'Limit'} . " " .
        $q->textfield(-name=>'limite',-size=>5,-value=>$limit) . 
        $lang{'records'} . "<br>" .
        $lang{"Page"} . 
        $q->popup_menu(-name=>'pagina',-values=>\@valores,-labels=>\%labels) . 
        "";

$res .= $q->submit(-name=>$lang{'Show-Info'}) . 
        $q->hidden(-name=>'offset',-default=>$offset,-override=>1)."<br>";

my $arr;
$res.="<table border=1 width='90%'>";
$res.= "<tr>";

foreach my $i (@fields){
    my @valores=($i . ' ASC',$i . ' DESC');
    my %labels=($i . ' ASC'=>'ASC',
		$i . ' DESC'=>'DESC');
    $res.="<th>" . $fieldslabels{$i} . "<br><small class='sub'>" . $q->radio_group(-name=>'order',-values=>\@valores,-labels=>\%labels) . "</small><br></th>";
}

$res.="</tr>";
my $color;
my $cont;

warn($logs) if($DEBUG ==1);
$sth=$dbh->prepare($logs) || die ("Error Preparing: " . $logs . " - " . $dbh->errstr) ;
$sth->execute || die ("Error Executing: " . $logs . " - " . $dbh->errstr) ;
while(my $arr=$sth->fetchrow_arrayref){
    $color=$color1 ne $color ? $color1 : $color2;
    $res.="<tr bgcolor='" . $color . "'>";
    $cont=0;
    foreach my $field (@$arr){
	# If you wish to customize the values in the table rows, add them here

	if($field_sem{$fields[$cont]} eq 'status'){
	    if ($field eq '1') {
		$field='<blink><b class="online">Online</b></blink>';
	    } elsif ($field eq '2') {
	        $field='Offline';
	    } elsif ($field eq '3') {
	        $field='Intrpt';
	    } 
	}

	elsif($field_sem{$fields[$cont]} eq 'Reason_Discon'){
	    if ($field==0 || $Cisco_Disconnect_Cause{$field} eq '') {
		$field = $lang{'Unknown'} . "(" . $field . ")";
	    } else {
	    	$field = $Cisco_Disconnect_Cause{$field};
	    }
	}
	
	# Show acct_session_time in Minutes
	elsif($field_sem{$fields[$cont]} eq 'acct_session_time'){
	    my $min=int($field/60);
	    my $hrs=int($min/60);
	    $field=$hrs . ":" . ($min-$hrs*60);
	}
	
	$field="-" if(!$field);
	$res.="<td align='center'>" .  $field . "</td>";
	$cont++;
    }
    $res.= "</tr>\n";
}

$res.="</table>";
$res.=$q->end_form;
$sth->finish;
$dbh->disconnect;


### Finally Print the page

print $q->header;
print $q->start_html(-title=>$lang{"Title"},-style=>{'src'=>'/radius.css'});
print $res;
print $q->end_html;
