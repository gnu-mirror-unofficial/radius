<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<!--
   radius.php - a PHP script that imitates functionality of a NAS.
   Copyright (C) 2004, 2007 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff

   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. -->

<?php
/* These are the only configurable values in this script:

/* Gives the program name of this script. Change it only if you chose
   to rename the program */
$progname = "radius.php";

/* Base reference URL for the script. Make sure it ends with a slash */
$base_href = "http://gray.farlep.net/test/";

/* IP address of this `NAS'. It is a string. */
$nas_ip_address = "10.10.10.1";
?>

<html>
<head>
 <title>GNU Radius NAS simulator</title>
 <?php echo "<base href=\"$base_href\">" ?>
 <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
</head>
<body bgcolor="#ffffff">
<?php

/* Produce initial form */
function initial_form()
{
	echo <<<EOT
<table>
<tr>
 <td>
  User Name
 </td>
 <td>
  <input name="username" tabindex="1">
 </td>
</tr>
<tr>
 <td>
  Password
 </td>
 <td>
  <input type="password" name="password" tabindex="2">
 </td>
</tr>
<tr>
 <td>
  Session Id
 </td>
 <td>
  <input name="session-id" tabindex="3">
 </td>
</tr>
<tr>
 <td>
  Port No.
 </td>
 <td>
  <input name="port-id" tabindex="4">
 </td>
</tr>
<tr>
 <td>
  Action:
 </td>
 <td>
  <select name="action">
EOT;
$actions = array('Authentication',
                 'Authentication and Accounting Start on Success',
                 'Accounting Start',
                 'Accounting Stop');
if (isset($_REQUEST['action']))
	$selected = $_REQUEST['action'];
else
	$selected = 0;

for ($i = 0; $i < 4; $i++) {
	print "<option value=$i";
	if ($i == $selected)
		print " selected";
	print ">$actions[$i]</option>\n";
}

echo <<<EOT
  </select>
 </td> 
</tr>
<tr>
 <td colspan="2" align="center">
  <input type="submit" name="submit" value="Submit" tabindex="3">
 </td>
</tr>
</table>
EOT;
}

/* Print a table row displaying attribute name $attr and its value $value.
   The exact representation of the latter is chosen based on the attribuite
   type */
function print_attribute($attr, $value)
{
	if (is_array($value)) {
		/* This means there were several instances of this
                   attribute in the packet. Mod_radius.c packs them all
	           into a single array element */
		foreach ($value as $val) 
			print_attribute($attr, $val);
		return;
	}
	echo "<tr><td><code>$attr</code></td><td>";
	if (radius_attribute_type($attr) == TYPE_IPADDR)
		echo long2ip($value);
	else if (is_long($value)
                 && $dictval = radius_lookup_value($attr, $value))
		echo $dictval;
	else 
		echo $value;
	echo "</td></tr>\n";
}

/* Display the radius server reply. $code is the reply code, $reply
   is the array of attribute values, indexed by attribute names,
   $msg is the concatenated value of all Reply-Message pairs encountered
   in the request */
function print_reply($code,$reply,$msg)
{
	echo <<<EOT
<table>
<tr>
 <td>
  <b>Reply code:</b>
 </td>
 <td>
  $code
 </td>
</tr>
<tr>
 <td>
  <b>Reply message:</b>
 </td>
 <td>
  $msg
 </td>
</tr>
<tr>
 <td>
  <b>Reply pairs:</b>
 </td>
 <td>
  <table border="1">
EOT;

if (isset($reply))
  foreach ($reply as $attr => $value) {
	/* Take care not to display Reply-Message attributes, as they have
           already been displayed. */
	if ($attr != "Reply-Message")
		print_attribute($attr, $value);
  }

echo <<<EOT
  </table>
 </td>
</tr>
</table>
EOT;
}

/* Print the page footer */
function print_footer()
{
	global $progname;

	echo <<<EOT
<hr>
<center>
<a href="$progname">Return to the start page</a>
</center>
EOT;
}

/* Send and process an Access-Request. Mandatory arguments are $username and
   $password. $state is optional. */
function auth($username, $password, $state)
{
	global $code, $reply, $msg, $nas_ip_address;

	$request = array();
	$request["User-Name"] = $username;
	$request["User-Password"] = $password;
	$request["NAS-IP-Address"] = $nas_ip_address;
	if (isset($state))
		$request["State"] = $state;

	$code = radius_query(PORT_AUTH, RT_ACCESS_REQUEST, $request,
                             $reply, $msg);

	switch ($code) {
	case RT_ACCESS_ACCEPT:
		echo "<h2>Authentication passed</h2>";
		print_reply($code, $reply, $msg);
		if ($_REQUEST['action'] == 1)
			acct($_REQUEST['username'], 'Start');
		break;

	case RT_ACCESS_REJECT:
		echo "<h2>Access Denied.</h2>";
		print_reply($code, $reply, $msg);
		break;

	case RT_ACCESS_CHALLENGE:
		/* FIXME: Just like radauth does, we suppose that
	           Access-Challenge response means sending a Livingston-style
	           menu, which is not always true. */
		echo "<h2>User Menu:</h2>";
		echo "<pre>$msg</pre>";
		echo "<p>Enter your choice: ";
		echo '<input name="choice" tabindex="1">';
		echo '<input type="submit" name="submit" value="Submit" tabindex="2">';
		/* Preserve the values we will need in the next submit */
		echo '<input type="hidden" name="username" value="' .
                     $username . '">';
		echo '<input type="hidden" name="state" value="' .
		     $reply['State'] . '">';
		echo '<input type="hidden" name="action" value="' .
		     $_REQUEST['action'] . '">';
		break;

	default:
		echo "<h2>Authentication failed</h2>";
		print_reply($code,$reply,$msg);
		break;
	}

	return $code;
}

/* Send an Accounting-Request and display its results */
function acct($username,$type)
{
	global $code, $reply, $msg;

	$request = array();
	$request["User-Name"] = $username;
	$request["NAS-IP-Address"] = "213.130.0.11";
	$request["NAS-Port-Id"] = $_REQUEST['port-id'];
	$request["Acct-Status-Type"] = $type;
	$request["Acct-Session-Id"] = $_REQUEST['session-id'];
	$code = radius_query(PORT_ACCT, RT_ACCOUNTING_REQUEST, $request,
                             $reply, $msg);
	echo "<h2>Accounting Results</h2>";
	print_reply($code, $reply, $msg);
}
?>

<center>
<h1>GNU Radius NAS Simulator</h1>
</center>
<hr>
<?php
/* Main procedure */

if (!extension_loaded('mod_radius.so') && dl('mod_radius.so') == FALSE)
	die('Cannot load mod_radius.so');

/* Caling this could help you debugging your script:
   radius_set_debug("radpdu,radsrv"); */


echo "<form action=\"$progname\" method=\"post\">";

if (isset($_REQUEST['choice'])) {
	auth($_REQUEST['username'], $_REQUEST['choice'], $_REQUEST['state']);
	print_footer();	
} else if (isset($_REQUEST['submit'])) {
	switch ($_REQUEST['action']) {
	case 0:
	case 1:
		auth($_REQUEST['username'], $_REQUEST['password']);
		break;

	case 2:
		acct($_REQUEST['username'], 'Start');
		break;

	case 3:
		acct($_REQUEST['username'], 'Stop');
	}
	print_footer();	
} else
	initial_form();
?>
    
</form>
    
</body>
</html>
