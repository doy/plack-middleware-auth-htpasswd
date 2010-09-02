package Plack::Middleware::Auth::Htpasswd;
use strict;
use warnings;
use base 'Plack::Middleware';
use Plack::Util::Accessor qw(realm file file_root);
use Plack::Request;

use Authen::Htpasswd;
use MIME::Base64;
use Path::Class ();

# ABSTRACT: http basic authentication through apache-style .htpasswd files

=head1 SYNOPSIS

  use Plack::Builder;
  my $app = sub { ... };

  builder {
      enable "Auth::Htpasswd", file => '/path/to/.htpasswd';
      $app;
  };

or

  builder {
      enable "Auth::Htpasswd", file_root => '/path/to/my/static/files';
      $app;
  };
  
=head1 DESCRIPTION

This middleware enables HTTP Basic authenication, based on the users in an
L<Apache-style htpasswd file|http://httpd.apache.org/docs/2.0/programs/htpasswd.html>.
You can either specify the file directly, through the C<file> option, or use
the C<file_root> option to specify the root directory on the filesystem that
corresponds to the web application root. This second option is more useful when
using an app that is closely tied to the filesystem, such as
L<Plack::App::Directory>. If C<file_root> is used, the requested path will be
inspected, and a file named C<.htpasswd> will be checked in each containing
directory, up to the C<file_root>. The first one found will be used to validate
the requested user.

=head1 CONFIGURATION

=head2 file

Name of a .htpasswd file to read authentication information from. Required if
C<file_root> is not set.

=head2 file_root

Path to the on-disk directory that corresponds to the root URL path of the app.
Required C<file> is not set, and ignored if C<file> is set.

=head2 realm

Realm name to display in the basic authentication dialog. Defaults to
'restricted area'.

=cut

sub prepare_app {
    my $self = shift;
    die "must specify either file or file_root"
        unless defined $self->file || $self->file_root;
}

sub call {
    my($self, $env) = @_;
    my $auth = $env->{HTTP_AUTHORIZATION};
    return $self->unauthorized
        unless $auth && $auth =~ /^Basic (.*)$/;

    my $auth_string = $1;
    my ($user, $pass) = split /:/, (MIME::Base64::decode($auth_string) || ":");
    $pass = '' unless defined $pass;

    if ($self->authenticate($env, $user, $pass)) {
        $env->{REMOTE_USER} = $user;
        return $self->app->($env);
    }
    else {
        return $self->unauthorized;
    }
}

sub _check_password {
    my $self = shift;
    my ($file, $user, $pass) = @_;
    my $htpasswd = Authen::Htpasswd->new($file);
    my $htpasswd_user = $htpasswd->lookup_user($user);
    return unless $htpasswd_user;
    return $htpasswd_user->check_password($pass);
}

sub authenticate {
    my $self = shift;
    my ($env, $user, $pass) = @_;

    return $self->_check_password($self->file, $user, $pass)
        if defined $self->file;

    my $path = Plack::Request->new($env)->path;
    my $dir = Path::Class::Dir->new($self->file_root);
    my @htpasswd = $path ne '/'
        ? reverse
          map { $_->file('.htpasswd')->stringify }
          map { $dir = $dir->subdir($_) }
          split m{/}, $path
        : ($dir->file('.htpasswd')->stringify);

    for my $htpasswd (@htpasswd) {
        next unless -f $htpasswd && -r _;
        return $self->_check_password($htpasswd, $user, $pass);
    }

    return;
}

sub unauthorized {
    my $self = shift;
    my $body = 'Authorization required';
    return [
        401,
        [
            'Content-Type' => 'text/plain',
            'Content-Length' => length $body,
            'WWW-Authenticate' => 'Basic realm="'
                                . ($self->realm || "restricted area")
                                . '"'
        ],
        [ $body ],
    ];
}

=head1 SEE ALSO

L<Plack>

L<Plack::Middleware::Auth::Basic>

=head1 CREDITS

Large parts of this code were modeled after (read: stolen from)
L<Plack::Middleware::Auth::Basic> by Tatsuhiko Miyagawa.

=cut

1;
