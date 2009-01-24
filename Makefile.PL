use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Net::LDAP::Server::Test',
    AUTHOR              => 'Peter Karman <karman@cpan.org>',
    VERSION_FROM        => 'lib/Net/LDAP/Server/Test.pm',
    ABSTRACT_FROM       => 'lib/Net/LDAP/Server/Test.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'IO::Socket' => 0,
        'IO::Select' => 0,
        'Net::LDAP::Server' => '0.3',
        'Net::LDAP'  => 0,
        'Data::Dump' => 0,

    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Net-LDAP-Server-Test-*' },
);
