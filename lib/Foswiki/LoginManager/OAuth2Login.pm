# Module of Foswiki Collaboration Platform, http://Foswiki.org/
#
# Copyright (C) 2010-12 Sven Dowideit, SvenDowideit@fosiki.com
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License, or (at your option) any later version. For
# more details read LICENSE in the root of this distribution.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# As per the GPL, removal of this notice is prohibited.

=pod

---+ package Foswiki::LoginManager::OAuth2Login

Thie OAuth2Login class uses the Drupal session cookie to auto-login into Foswiki

=cut

package Foswiki::LoginManager::OAuth2Login;

use strict;
use Assert;

use Foswiki ();
use Foswiki::LoginManager::TemplateLogin ();

use Net::OAuth2::Client;
use HTML::Entities;
use JSON;

@Foswiki::LoginManager::OAuth2Login::ISA = ('Foswiki::LoginManager::TemplateLogin');

sub new {
    my ( $class, $session ) = @_;

    my $this = bless( $class->SUPER::new($session), $class );
    $session->enterContext('can_login');

    return $this;
}

sub finish {
    my $this = shift;

    $this->SUPER::finish();
    return;
}

=pod

---++ ObjectMethod loadSession()

from facebook



=cut

sub loadSession {
    my $this  = shift;
    my $foswiki = $this->{session};
    my $query = $foswiki->{request};

    ASSERT( $this->isa('Foswiki::LoginManager::OAuth2Login') ) if DEBUG;

    # LoginManager::loadSession does a redirect on logout, so we have to deal with logout before it.
    my $authUser = $this->SUPER::loadSession();
print STDERR "before = authUser = $authUser\n";
	return $authUser if ($authUser ne $Foswiki::cfg{DefaultUserLogin});

#    return $foswiki->{response}
#      ->redirect( -url => client()->authorize_url ) if (!defined $query->param('code'));
#    return $this->SUPER::loadSession() if (!defined $query->param('code'));

	if (defined($query->param('code'))) {
		my $access_token =  client()->get_access_token($query->param('code'));
		 if ($access_token->{error}) {
			print STDERR "get_access_token: Error: " . $access_token->to_string;
			$this->userLoggedIn($Foswiki::cfg{DefaultUserLogin});
		    return $authUser;
		}
		my $content = '<h2>Access token retrieved successfully!</h2><p>' . encode_entities($access_token->to_string) . '</p>';
		my $response = $access_token->get('https://graph.facebook.com/me');
		if ($response->is_success) {
			#$content .= '<h2>Protected resource retrieved successfully!</h2><p>' . encode_entities($response->decoded_content) . '</p>';
	use Data::Dumper;
	$content .= 'Protected resource retrieved successfully: '.Dumper($response)."\n";
			#actually, login might be irrelevant, but cuid needs to be url (or some guid that cna be mapped to more than one url..
			if (defined($response->{_content})) {
				my $json = decode_json($response->{_content});
				$authUser = $json->{name};
				$authUser =~ s/\s//g;
				$this->userLoggedIn($authUser);
return $foswiki->{response}
      ->redirect( -url => Foswiki::Func::getScriptUrl(undef, undef,'view'));
			}
		}
		else {
			$content .= '<p>Error: ' . $response->status_line . '</p>';
			$this->userLoggedIn($Foswiki::cfg{DefaultUserLogin});
		}
		$content =~ s[\n][<br/>\n]g;
		print STDERR $content;
	}

print STDERR "after = authUser = $authUser\n";

    return $authUser;
}


=begin TML

---++ ObjectMethod loginUrl () -> $loginUrl

just use facebook login atm?

=cut

sub loginUrl {
    my $this    = shift;

    my $foswiki = $this->{session};
    my $query = $foswiki->{request};

    ASSERT( $this->isa('Foswiki::LoginManager::OAuth2Login') ) if DEBUG;


      return client()->authorize_url ;
#use the foswiki templlogin
    return $this->SUPER::loginUrl() if (defined $query->param('sudo'));

    #redirect client()->authorize_url;
return $foswiki->{response}
      ->redirect( -url => client()->authorize_url );
}

=begin TML

get a client object

        facebook:
                name: 'Facebook'
                client_id: '123456789'
                client_secret: '120398471234'
                site: 'https://graph.facebook.com'
                protected_resource_path: '/me'

getScriptUrl('x','y','view','#'=>'XXX',a=>1,b=>2)

=cut

sub client {
    my $this    = shift;

	if (!defined($this->{OAuth_client})) {
		$this->{OAuth_client} = Net::OAuth2::Client->new(
			'123456789',
			'9872163498',
			site => 'https://graph.facebook.com',
#not used for facebook
#			authorize_path => config->{sites}{$site_id}{authorize_path},
#			access_token_path => config->{sites}{$site_id}{access_token_path},
#			access_token_method => config->{sites}{$site_id}{access_token_method},
#		)->web_server(redirect_uri => fix_uri(uri_for("/got/$site_id")));
		)->web_server(redirect_uri => Foswiki::Func::getScriptUrl(undef, undef,'login','site'=>'facebook',
            'foswiki_origin' => Foswiki::LoginManager::TemplateLogin::_packRequest($this->{session})
));
	}

    return $this->{OAuth_client} ;
}

1;
