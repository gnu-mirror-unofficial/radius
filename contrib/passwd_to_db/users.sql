-- MySQL dump 8.22
--
-- Host: localhost    Database: passwd
---------------------------------------------------------
-- Server version	3.23.57

--
-- Table structure for table 'users'
--

CREATE TABLE users (
  username varchar(128) NOT NULL default '',
  cryptpass varchar(30) NOT NULL default '',
  UID int(10) NOT NULL default '666' auto_increment,
  GID int(10) default NULL,
  GECOS varchar(128) default NULL,
  home varchar(128) default NULL,
  shell varchar(128) default '/usr/local/bin/bash',
  PRIMARY KEY  (UID)
) TYPE=MyISAM;

ALTER TABLE users AUTO_INCREMENT = 1000

--
-- Dumping data for table 'users'
--



