
#
# Table structure for table 'calls_title'
#
CREATE TABLE calls_title (
  var char(32),
  title char(128)
);

#
# Dumping data for table 'calls_title'
#

INSERT INTO calls_title VALUES ('status','Estado');
INSERT INTO calls_title VALUES ('user_name','Login');
INSERT INTO calls_title VALUES ('Event_Date_Time','Fecha');
INSERT INTO calls_title VALUES ('nas_ip_address','IP NAS');
INSERT INTO calls_title VALUES ('nas_port_id','Puerto NAS');
INSERT INTO calls_title VALUES ('acct_session_id','Ident Sesion');
INSERT INTO calls_title VALUES ('acct_session_time','Tiempo Conex.');
INSERT INTO calls_title VALUES ('acct_input_octets','Bytes entrada');
INSERT INTO calls_title VALUES ('acct_output_octets','Bytes Salida');
INSERT INTO calls_title VALUES ('connect_term_reason','Razon term. conex.');
INSERT INTO calls_title VALUES ('framed_ip_address','IP Asignada');
INSERT INTO calls_title VALUES ('called_station_id','Estacion llamada');
INSERT INTO calls_title VALUES ('calling_station_id','Num. Origen');

