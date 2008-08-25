package Net::LDAP::Server::Test;

use warnings;
use strict;
use Carp;
use IO::Select;
use IO::Socket;

our $VERSION = '0.07';

=head1 NAME

Net::LDAP::Server::Test - test Net::LDAP code

=head1 SYNOPSIS

    use Test::More tests => 10;
    use Net::LDAP::Server::Test;
    
    ok( my $server = Net::LDAP::Server::Test->new(8080), 
            "test LDAP server spawned");
    
    # connect to port 8080 with your Net::LDAP code.
    ok(my $ldap = Net::LDAP->new( 'localhost', port => 8080 ),
             "new LDAP connection" );
             
    # ... test stuff with $ldap ...
    
    # server will exit when you call final LDAP unbind().
    ok($ldap->unbind(), "LDAP server unbound");

=head1 DESCRIPTION

Now you can test your Net::LDAP code without having a real
LDAP server available.

=head1 METHODS

Only one user-level method is implemented: new().

=cut

{

    package    # fool Pause
        MyLDAPServer;

    use strict;
    use warnings;
    use Carp;

    #use Data::Dump qw( dump );

    use Net::LDAP::Constant qw(LDAP_SUCCESS);
    use Net::LDAP::Entry;
    use Net::LDAP::Filter;
    use Net::LDAP::FilterMatch;

    use base 'Net::LDAP::Server';
    use fields qw( _flags );

    use constant RESULT_OK => {
        'matchedDN'    => '',
        'errorMessage' => '',
        'resultCode'   => LDAP_SUCCESS
    };

    our %Data;    # package data lasts as long as $$ does.

    # constructor
    sub new {
        my ( $class, $sock, %args ) = @_;
        my $self = $class->SUPER::new($sock);
        printf "Accepted connection from: %s\n", $sock->peerhost();
        $self->{_flags} = \%args;
        return $self;
    }

    sub unbind {
        my $self    = shift;
        my $reqData = shift;
        return RESULT_OK;
    }

    # the bind operation
    sub bind {
        my $self    = shift;
        my $reqData = shift;
        return RESULT_OK;
    }

    # the search operation
    sub search {
        my $self = shift;

        if ( defined $self->{_flags}->{data} ) {
            return $self->_search_user_supplied_data(@_);
        }
        elsif ( defined $self->{_flags}->{auto_schema} ) {
            return $self->_search_auto_schema_data(@_);
        }
        else {
            return $self->_search_default_test_data(@_);
        }
    }

    sub _search_user_supplied_data {
        my ( $self, $reqData ) = @_;

        #warn 'SEARCH USER DATA: ' . dump \@_;
        return RESULT_OK, @{ $self->{_flags}->{data} };
    }

    sub _search_auto_schema_data {
        my ( $self, $reqData, $reqMsg ) = @_;

        #warn 'SEARCH SCHEMA: ' . dump \@_;

        my @results;
        my $base    = $reqData->{baseObject};
        my $scope   = $reqData->{scope} || 'sub';
        my @filters = ();

        if ( $scope ne 'base' ) {
            if ( exists $reqData->{filter} ) {

                push( @filters,
                    bless( $reqData->{filter}, 'Net::LDAP::Filter' ) );

            }
        }

        #warn "stored Data: " . dump \%Data;
        #warn "searching for " . dump \@filters;

        # loop over all keys looking for match
        for my $dn ( keys %Data ) {

            next unless $dn =~ m/$base$/;

            if ( $scope eq 'base' ) {
                next unless $dn eq $base;
            }
            elsif ( $scope eq 'one' ) {
                next unless $dn =~ m/^(\w+=\w+,)?$base$/;
            }

            my $entry = $Data{$dn};

            #warn "trying to match $dn : " . dump $entry;

            my $match = 0;
            for my $filter (@filters) {

                if ( $filter->match($entry) ) {

                    #warn "$f matches entry $dn";
                    $match++;
                }
            }

            #warn "matched $match";
            if ( $match == scalar(@filters) ) {    # or $dn eq $base ) {

                # clone the entry so that client cannot modify %Data
                push( @results, $entry->clone );
            }
        }

       #warn "search results for " . dump($reqData) . "\n: " . dump \@results;

        return RESULT_OK, @results;

    }

    sub _search_default_test_data {
        my ( $self, $reqData ) = @_;

        #warn 'SEARCH DEFAULT: ' . dump \@_;

        my $base = $reqData->{'baseObject'};

        # plain die if dn contains 'dying'
        die("panic") if $base =~ /dying/;

        # return a correct LDAPresult, but an invalid entry
        return RESULT_OK, { test => 1 } if $base =~ /invalid entry/;

        # return an invalid LDAPresult
        return { test => 1 } if $base =~ /invalid result/;

        my @entries;
        if ( $reqData->{'scope'} ) {

            # onelevel or subtree
            for ( my $i = 1; $i < 11; $i++ ) {
                my $dn    = "ou=test $i,$base";
                my $entry = Net::LDAP::Entry->new;
                $entry->dn($dn);
                $entry->add(
                    dn => $dn,
                    sn => 'value1',
                    cn => [qw(value1 value2)]
                );
                push @entries, $entry;
            }

            my $entry1 = Net::LDAP::Entry->new;
            $entry1->dn("cn=dying entry,$base");
            $entry1->add(
                cn => 'dying entry',
                description =>
                    'This entry will result in a dying error when queried'
            );
            push @entries, $entry1;

            my $entry2 = Net::LDAP::Entry->new;
            $entry2->dn("cn=invalid entry,$base");
            $entry2->add(
                cn => 'invalid entry',
                description =>
                    'This entry will result in ASN1 error when queried'
            );
            push( @entries, $entry2 );

            my $entry3 = Net::LDAP::Entry->new;
            $entry3->dn("cn=invalid result,$base");
            $entry3->add(
                cn => 'invalid result',
                description =>
                    'This entry will result in ASN1 error when queried'
            );
            push @entries, $entry3;
        }
        else {

            # base
            my $entry = Net::LDAP::Entry->new;
            $entry->dn($base);
            $entry->add(
                dn => $base,
                sn => 'value1',
                cn => [qw(value1 value2)]
            );
            push @entries, $entry;
        }
        return RESULT_OK, @entries;
    }

    sub add {
        my ( $self, $reqData, $reqMsg ) = @_;

        #warn 'ADD: ' . dump \@_;

        my $entry = Net::LDAP::Entry->new;
        my $key   = $reqData->{objectName};
        $entry->dn($key);
        for my $attr ( @{ $reqData->{attributes} } ) {
            $entry->add( $attr->{type} => \@{ $attr->{vals} } );
        }

        $Data{$key} = $entry;

        if ( exists $self->{_flags}->{active_directory} ) {
            $self->_add_AD( $reqData, $reqMsg, $key, $entry, \%Data );
        }

        return RESULT_OK;
    }

    sub modify {
        my ( $self, $reqData, $reqMsg ) = @_;

        #warn 'MODIFY: ' . dump \@_;

        my $key = $reqData->{object};
        if ( !exists $Data{$key} ) {
            croak "can't modify a non-existent entry: $key";
        }

        my @mods = @{ $reqData->{modification} };
        for my $mod (@mods) {
            my $attr  = $mod->{modification}->{type};
            my $vals  = $mod->{modification}->{vals};
            my $entry = $Data{$key};
            $entry->replace( $attr => $vals );
        }

        if ( $self->{_flags}->{active_directory} ) {
            $self->_modify_AD( $reqData, $reqMsg, \%Data );
        }

        return RESULT_OK;

    }

    sub delete {
        my ( $self, $reqData, $reqMsg ) = @_;

        #warn 'DELETE: ' . dump \@_;

        my $key = $reqData;
        if ( !exists $Data{$key} ) {
            croak "can't delete a non-existent entry: $key";
        }
        delete $Data{$key};

        return RESULT_OK;

    }

    sub modifyDN {
        my ( $self, $reqData, $reqMsg ) = @_;

        #warn "modifyDN: " . dump \@_;

        my $oldkey = $reqData->{entry};
        my $newkey = join( ',', $reqData->{newrdn}, $reqData->{newSuperior} );
        if ( !exists $Data{$oldkey} ) {
            croak "can't modifyDN for non-existent entry: $oldkey";
        }
        my $entry    = $Data{$oldkey};
        my $newentry = $entry->clone;
        $newentry->dn($newkey);
        $Data{$newkey} = $newentry;

        #warn "created new entry: $newkey";
        if ( $reqData->{deleteoldrdn} ) {
            delete $Data{$oldkey};

            #warn "deleted old entry: $oldkey";
        }

        return RESULT_OK;
    }

    sub compare {
        my ( $self, $reqData, $reqMsg ) = @_;

        #warn "compare: " . dump \@_;

        return RESULT_OK;
    }

    sub abandon {
        my ( $self, $reqData, $reqMsg ) = @_;

        #warn "abandon: " . dump \@_;

        return RESULT_OK;
    }

    my $token_counter = 100;
    my $sid_str       = 'S-01-5-21-350811113-3086823889-3317782326-1234';

    sub _sid2string {
        my $sid = shift;
        my (@unpack) = unpack( "H2 H2 n N V*", $sid );
        my ( $sid_rev, $num_auths, $id1, $id2, @ids ) = (@unpack);
        return join( "-", "S", $sid_rev, ( $id1 << 32 ) + $id2, @ids );
    }

    sub _string2sid {
        my $string = shift;
        my (@split) = split( m/\-/, $string );
        my ( $prefix, $sid_rev, $auth_id, @ids ) = (@split);
        if ( $auth_id != scalar(@ids) ) {
            die "bad string: $string";
        }

        my $sid = pack( "C4", "$sid_rev", "$auth_id", 0, 0 );
        $sid .= pack( "C4",
            ( $auth_id & 0xff000000 ) >> 24,
            ( $auth_id & 0x00ff0000 ) >> 16,
            ( $auth_id & 0x0000ff00 ) >> 8,
            $auth_id & 0x000000ff );

        for my $i (@ids) {
            $sid .= pack( "I", $i );
        }

        return $sid;
    }

    sub _add_AD {
        my ( $server, $reqData, $reqMsg, $key, $entry, $data ) = @_;

        for my $attr ( @{ $reqData->{attributes} } ) {
            if ( $attr->{type} eq 'objectClass' ) {
                if ( grep { $_ eq 'group' } @{ $attr->{vals} } ) {

                    # groups
                    $token_counter++;
                    ( my $group_sid_str = $sid_str )
                        =~ s/-1234$/-$token_counter/;
                    $entry->add( 'primaryGroupToken' => $token_counter );
                    $entry->add( 'objectSID'         => "$group_sid_str" );

                }
                else {

                    # users
                    my $gid = $entry->get_value('primaryGroupID');
                    ( my $user_sid_str = $sid_str ) =~ s/-1234$/-$gid/;
                    my $user_sid = _string2sid($user_sid_str);
                    $entry->add( 'objectSID'         => $user_sid );
                    $entry->add( 'distinguishedName' => $key );

                }
            }

        }

        _update_groups($data);

        #dump $reqData;
        #dump $data;

    }

    # AD stores group assignments in 'member' attribute
    # of each group. 'memberOf' is linked internally to that
    # attribute. We set 'memberOf' here if mimicing AD.
    sub _update_groups {
        my $data = shift;

        # all groups
        for my $key ( keys %$data ) {
            my $entry = $data->{$key};

            #warn "groups: update groups for $key";
            if ( !$entry->get_value('sAMAccountName') ) {

                #dump $entry;

                # group entry.
                # are the users listed in member
                # still assigned in their memberOf?
                my %users = map { $_ => 1 } $entry->get_value('member');
                for my $dn ( keys %users ) {

                    #warn "User $dn is a member in $key";
                    my $user = $data->{$dn};
                    my %groups = map { $_ => 1 } $user->get_value('memberOf');

                    # if $user does not list $key (group) as a memberOf,
                    # then add it.
                    if ( !exists $groups{$key} && exists $users{$dn} ) {
                        $groups{$key}++;
                        $user->replace( memberOf => [ keys %groups ] );
                    }
                }

            }

        }

        # all users

        for my $key ( keys %$data ) {
            my $entry = $data->{$key};

            #warn "users: update groups for $key";
            if ( $entry->get_value('sAMAccountName') ) {

                #dump $entry;

                # user entry
                # get its groups and add this user to each of them.
                my %groups = map { $_ => 1 } $entry->get_value('memberOf');
                for my $dn ( keys %groups ) {
                    my $group = $data->{$dn};
                    my %users
                        = map { $_ => 1 } ( $group->get_value('member') );

                    # if group no longer lists this user as a member,
                    # remove group from memberOf
                    if ( !exists $users{$key} ) {
                        delete $groups{$dn};
                        $entry->replace( memberOf => [ keys %groups ] );
                    }
                }

            }
        }

    }

    sub _modify_AD {
        my ( $server, $reqData, $reqMsg, $data ) = @_;

        #dump $data;
        _update_groups($data);

        #Data::Dump::dump $data;

    }

}    # end MyLDAPServer

=head2 new( I<port>, I<key_value_args> )

Create a new server. Basically this just fork()s a child process
listing on I<port> and handling requests using Net::LDAP::Server.

I<port> defaults to 10636.

I<key_value_args> may be:

=over

=item data

I<data> is optional data to return from the Net::LDAP search() function.
Typically it would be an array ref of Net::LDAP::Entry objects.

=item auto_schema

A true value means the add(), modify() and delete() methods will
store internal in-memory data based on DN values, so that search()
will mimic working on a real LDAP schema.

=item active_directory

Work in Active Directory mode. This means that entries are automatically
assigned a objectSID, and some effort is made to mimic the member/memberOf
linking between AD Users and Groups.

=back

new() will croak() if there was a problem fork()ing a new server.

Returns a Net::LDAP::Server::Test object, which is just a
blessed reference to the PID of the forked server.

=cut

sub new {
    my $class = shift;
    my $port  = shift || 10636;
    my %arg   = @_;

    if ( $arg{data} and $arg{auto_schema} ) {
        croak
            "cannot handle both 'data' and 'auto_schema' features. Pick one.";
    }

    my $pid = fork();

    if ( !defined $pid ) {
        croak "can't fork a LDAP test server: $!";
    }
    elsif ( $pid == 0 ) {

        # the child (server)
        my $sock = IO::Socket::INET->new(
            Listen    => 5,
            Proto     => 'tcp',
            Reuse     => 1,
            LocalPort => $port
        );

        warn "creating new LDAP server on port $port ... \n";

        my $sel = IO::Select->new($sock);
        my %Handlers;
        while ( my @ready = $sel->can_read ) {
            foreach my $fh (@ready) {
                if ( $fh == $sock ) {

                    # let's create a new socket
                    my $psock = $sock->accept;
                    $sel->add($psock);
                    $Handlers{*$psock} = MyLDAPServer->new( $psock, %arg );

                    #warn "new socket created";
                }
                else {
                    my $result = $Handlers{*$fh}->handle;
                    if ($result) {

                        # we have finished with the socket
                        $sel->remove($fh);
                        $fh->close;
                        delete $Handlers{*$fh};

                        # if there are no open connections,
                        # exit the child process.
                        if ( !keys %Handlers ) {
                            warn " ... shutting down server\n";
                            exit(0);
                        }
                    }
                }
            }
        }

        # if we get here, we had some kinda problem.
        croak "reached the end of while() loop prematurely";

    }
    else {

        # the parent (client).
        # hesitate a little to account for slow fork()s since
        # sleep() is not strictly portable.
        #warn "starting nap at " . localtime() . "\n";
        my $wait = time() + 2;
        while ( time() < $wait ) {
            1;
        }

        #warn "awake at " . localtime() . "\n";
        return bless( \$pid, $class );
    }

}

=head2 DESTROY

When a LDAP test server object is destroyed, waitpid() is called
on the associated child process. Typically this is unnecessary, but
implemented here as an exercise.

=cut

sub DESTROY {
    my $pid = ${ $_[0] };

    #warn "DESTROYing a LDAP server with pid $pid";

    # calling waitpid() here causes some tests to hang indefinitely if they
    # die prematurely.
    #my $epid = waitpid( $pid, 0 );

    #carp "$pid [$epid] exited with value $?";

}

=head1 AUTHOR

Peter Karman, C<< <karman at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-net-ldap-server-test at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-LDAP-Server-Test>.
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::LDAP::Server::Test

You can also look for information at:

=over 4

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-LDAP-Server-Test>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-LDAP-Server-Test>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-LDAP-Server-Test>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-LDAP-Server-Test>

=back

=head1 ACKNOWLEDGEMENTS

The Minnesota Supercomputing Institute C<< http://www.msi.umn.edu/ >>
sponsored the development of this software.

=head1 COPYRIGHT & LICENSE

Copyright 2007 by the Regents of the University of Minnesota.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=head1 SEE ALSO

Net::LDAP::Server

=cut

1;
