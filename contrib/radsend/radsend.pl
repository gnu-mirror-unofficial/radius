#! /usr/local/bin/perl 
# Copyright (C) 2004, 2007 <garcia_j14@tsm.es>
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
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

while ($_ = $ARGV[0], /^-/) {
    shift;
    last if /^--$/;
    if (/^--.*/ || /^-.*/) {
	push(@opts, "$_ ");
    } else {
	print "FOUND\n";
	$clave = uc($_);
	last;
    };
}

if (! defined $clave && defined $ARGV[0]) {
    $clave=uc($ARGV[0]);
}

if (! defined $clave != 0) {
    print "\nNo seas cafre, y mete algo como Dios manda ...\n";
    print "Uso: $0 palabra_clave\n\n";
    exit 1;
}

open (PAQUETES, "< paquetes.conf") or die "No tienes paquetes???";

while (<PAQUETES>) {
    if ($_ !~ /^#/) {
	@linea = split;
	if ($_ =~ /$clave/) {
	    if ($linea[1] =~ "send") {
		$puerto = $linea[2];
		$codigo = $linea[3];
	    } else {
		push(@atributos, "$linea[1] ");
	    }
	} elsif ("$linea[0]" =~ "DEFAULT" and $linea[1] =~ "send") {
	    if (not defined($puerto)) {
		$puerto = $linea[2];
		$codigo = $linea[3];
	    }
	}
    }
}

$cadena = "<<'EOF'\n send $puerto $codigo @atributos \nEOF\n";
system ("radtest @opts $cadena");

# EOF
