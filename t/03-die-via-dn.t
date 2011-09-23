#!/usr/bin/env perl
use Test::More tests => 12;

use strict;
use warnings;

use Carp;
use Data::Dump qw( dump );
use Net::LDAP;
use Net::LDAP::Entry;
use Net::LDAP::Server::Test;

my %opts = (
    port  => '10636',
    dnc   => 'ou=internal,dc=foo',
    debug => $ENV{PERL_DEBUG} || 0,
);

my $host = 'ldap://localhost:' . $opts{port};

ok( my $server = Net::LDAP::Server::Test->new( $opts{port} ),
    "spawn new server" );

my $ldap_connection = Net::LDAP->new( $host, %opts, );
$ldap_connection->bind();

my $ldap_result = $ldap_connection->search(
    base   => 'cn=users,cn=dev.o2.co.uk,cn=domains,cn=cproot,o=o2',
    scope  => 'sub',
    filter => 'uid=gjttest'
);

diag "Real user: " . dump($ldap_result);

$ldap_result = $ldap_connection->search(
    base   => 'uid=dying,cn=users,cn=dev.o2.co.uk,cn=domains,cn=cproot,o=o2',
    scope  => 'sub',
    filter => 'objectClass=*'
);

diag "Dying test: " . dump($ldap_result);

#sleep 10;

$ldap_connection = Net::LDAP->new( $host, %opts, );
$ldap_connection->bind();

$ldap_result = $ldap_connection->search(
    base   => 'cn=users,cn=dev.o2.co.uk,cn=domains,cn=cproot,o=o2',
    scope  => 'sub',
    filter => 'uid=invalid_result'
);

diag "Invalid Result test: " . dump($ldap_result);

$ldap_result = $ldap_connection->search(
    base   => 'cn=users,cn=dev.o2.co.uk,cn=domains,cn=cproot,o=o2',
    scope  => 'sub',
    filter => 'uid=invalid_entry'
);

diag "Invalid Entry test: " . dump($ldap_result);

undef $ldap_result;
my $error;

eval {
    local $SIG{ALRM} = sub {
        croak('LDAP timeout exceeded');
    };
    alarm 5;

    $ldap_result = $ldap_connection->search(
        base   => 'cn=users,cn=dev.o2.co.uk,cn=domains,cn=cproot,o=o2',
        scope  => 'sub',
        filter => 'uid=timeout',
    );

    alarm(0);
} or do {
    $error = $@;
};

diag "Timeout: " . dump($ldap_result) . dump($error);

