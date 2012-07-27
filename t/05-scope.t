use strict;
use warnings;

use Test::More;

use Net::LDAP;
use Net::LDAP::Server::Test;

my $port = 1024 + int rand(10000) + $$ % 1024;

ok( my $server = Net::LDAP::Server::Test->new( $port, auto_schema => 1 ), "spawn new server" );
ok( my $ldap = Net::LDAP->new("localhost:$port"), "new LDAP connection" );
ok( my $rc = $ldap->bind(), "LDAP bind()" );

my @scopes = qw(base one sub);

# Add our nested DNs
my $dn = my $base = "dc=example,dc=com";
for my $level (@scopes) {
    $dn = "cn=$level group,$dn";
    $ldap->add(
        $dn,
        attr => [
            cn          => "$level group",
            objectClass => 'Group',
        ],
    );
}

# Do scopes work?
my %expected = (
    'base' => 1,
    'one'  => 2,
    'sub'  => 3,
);

for my $scope (@scopes) {
    my $count = $expected{$scope};
    my $msg = $ldap->search(
        base    => "cn=base group,$base",
        scope   => $scope,
        filter  => '(objectClass=group)',
    );
    ok $msg, "searched with scope $scope";
    TODO: {
        local $TODO = "scope of 'one' doesn't work with spaces in the DN (yet)"
            if $scope eq 'one';
        is $msg->count, $count, "found $count";
    }
}

ok $ldap->unbind, "unbound";
done_testing;
