package Plack::Middleware::Auth::Htpasswd;
use strict;
use warnings;
use base 'Plack::Middleware';
use Plack::Util::Accessor qw(realm file file_root);
use Plack::Request;

use Authen::Htpasswd;
use MIME::Base64;
use Path::Class ();

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

    my $req = Plack::Request->new($env);
    my $dir = Path::Class::Dir->new($self->file_root);
    my @htpasswd = reverse
                   map { $_->file('.htpasswd')->stringify }
                   map { $dir = $dir->subdir($_) }
                   split m{/}, $req->path;

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

1;
