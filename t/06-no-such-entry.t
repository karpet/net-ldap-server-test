use strict;
use warnings;
use Test::More;
use Net::LDAP::Server::Test;
use Net::LDAP;
use Net::LDAP::LDIF;
use File::Temp qw(tempfile);

# Create ldif
my $ldif_entries = <<EOL;
dn: app=test
app: test
objectClass: top
objectClass: application

dn: msisdn=34610123123,app=test
objectClass: msisdn
msisdn: 34610123123

EOL

my ( $fh, $filename ) = tempfile();
print $fh $ldif_entries;
close $fh;

# Create and connect to server
ok( my $server = Net::LDAP::Server::Test->new( 12389, auto_schema => 1 ),
    "test LDAP server spawned" );
ok( my $ldap = Net::LDAP->new( 'localhost', port => 12389 ),
    "new LDAP connection" );

# Load ldif
my $ldif = Net::LDAP::LDIF->new( $filename, 'r', onerror => 'die',
    lowercase => 1 );
while ( not $ldif->eof ) {
    my $entry = $ldif->read_entry or die "Unable to parse entry";
    my $mesg = $ldap->add($entry);
    $mesg->code
        and die sprintf "Error adding entry [%s]: [%s]", $entry->dn,
        $mesg->error;
}
$ldif->done;

# Just make sure everything is ok :)
my $mesg = $ldap->search(
    base   => 'msisdn=34610123123,app=test',
    scope  => 'base',
    filter => 'objectClass=*'
);
is( $mesg->code, 0, 'msisdn found' );

# This should work. A base search to a non-existing entry should return 32
$mesg = $ldap->search(
    base   => 'msisdn=123456789,app=test',
    scope  => 'base',
    filter => 'objectClass=*'
);
is( $mesg->code,              32, 'msisdn not found' );
is( scalar( $mesg->entries ), 0,  'number of entries equals zero' );

done_testing;
