#!/usr/bin/perl
use 5.012;
use strict;
use warnings;
use IO::Socket::INET;
use IO::File;
use POE qw/ Wheel::ReadLine Wheel::ReadWrite Filter::Stream/;
use Getopt::Long;
use Time::HiRes qw/ time /;

my $VERSION = '0.3.1';

use constant {
    # RCON constants, packet types
    # Not likely to ever change, but I absolutely hate magic numbers.
    PASSWORD            => 3,
    COMMAND             => 2,
    RESPONSE            => 0,

    # This is the max packet size for an RCON packet
    # Sadly, this is *not* used when recv()ing in the POE::Wheel::ReadWrite as I have no way to specify it.
    # Only used in command mode.
    RECV_LENGTH         => 4096,

    ID_MAX              => 255,     # The next request is sent as request 1
    ID_CHAT             => 65535,   # MAXINT in this context, used in request_chat to know what is a response to that
    ID_PLAYERS          => 65534,   # Used in request_playerlist to destinguish it from any other userlist command
    ID_PASSWORD         => 1024,    # The ID used for authentication. If the response does not match in ID, we were rejected!

    DELAY_PLAYERLIST    => 10,      # I didn't like how these were magic numbers and I had to dig them up to tweak them.
    DELAY_GETCHAT       => 5,

    SOCKET_TIMEOUT      => 15,      # If there has been NOTHING on the socket for this amount of time, reconnect!
    SOCKET_TIMEOUT_CHECK => 5,      # How often to check if we're beyond the timeout

    NO_RESPONSE         => 'Server received, But no response!!', # The line the server sends when it has no response to give.
};
my %OPTIONS_DOC = (
    address => [
        'The address to connect to.',
        'Default is 127.0.0.1',
    ],
    port => [
        'The port RCON is listening on.',
        'Default is 27015',
    ],
    password => [
        'The server\'s administrator password.',
        'No default, must be specified.',
    ],
    verbose => [
        'Get more detaild information about the scripts inner workings.',
        'Defaults to off.',
    ],

    'log-file' => [
        'Path to where the script will log, if enabled.',
        'Defaults to '.$ENV{'HOME'}.'/ark_rcon.log',
    ],
    'log-enabled' => [
        'Enables logging to the specified file.',
        'Defaults to disabled.',
    ],
    'log-verbose' => [
        'Like --verbose, but only in the log.',
        'Implies --log-enabled',
        'Defaults to disabled.',
    ],
    'log-clobber' => [
        'Overwrite, rather than append to, the given log file.',
        'Does nothing unless logging is enabled',
        'Defaults to disabled, meaning any logging will be appended to the file.',
    ],

    command => [
        'Rather than running interactively, send this command and then disconnect.',
        'You can specify as many of these as you want.',
        'They are sent to the server in the order given.',
        'Defaults to nothing, meaning the script will run in interactive mode.',
    ],
    quiet => [
        'Suppress any output to the controlling terminal.',
        'Useful when running from a crontab, for example.',
        'Logging to file is *not* suppressed.',
        'Only makes sense with one or more --command instructions.',
    ],
    help => [
        'You\'re looking at it.',
    ],
);
my @OPTIONS_ORDER = qw/ !Connection address port password !Flow verbose command quiet help !Logging log-file log-enabled log-verbose log-clobber /;

launch();

exit 0;




# Some setup first (These are not valid events!)
sub launch {                    # Preparing ALL THE THINGS, selecting interactive or command mode, etc. Does basic commandline sanity check
    # I mostly made this a sub so it'll fold nicely in my VIM setup.

    # LeDefaults:
    my $address = '127.0.0.1';
    my $port = 27015;
    my $password;
    my @commands;
    my $quiet = 0;
    my $verbose = 0;
    my $log_file = $ENV{'HOME'}.'/ark_rcon.log';
    my $log_verbose = 0;
    my $log_enabled = 0;
    my $log_clobber = 0;
    my $help = 0;

    # Override them defaults!
    GetOptions(
        "address=s"     => \$address,
        "port=i"        => \$port,
        "password=s"    => \$password,
        "verbose"       => \$verbose,

        "log-file=s"    => \$log_file,
        "log-enabled"   => \$log_enabled,
        "log-verbose"   => \$log_verbose,
        "log-clobber"   => \$log_clobber,
        
        "command=s"     => \@commands,
        "quiet"         => \$quiet,

        "help"          => \$help,

    ) or die ("Invalid command line arguments.  Seek --help\n");


    if ($help){
        help_table();
        exit 0; # Because displaying help and then running seems very silly.
    }

    die "--password is required! Seek --help\n" unless defined $password;

    if ($log_verbose){
        $log_enabled = 1;
    }

    if ($quiet and not scalar @commands){
        die "--quiet is not available in interactive mode. Specify some --command parametes!\n";
    }

    my $initial_heap = {
        address         => $address,
        port            => $port,
        password        => $password,
        verbose         => $verbose,
        quiet           => $quiet,
        log_file        => $log_file,
        log_enabled     => $log_enabled,
        log_verbose     => $log_verbose,
        log_clobber     => $log_clobber,
    };

    if (scalar @commands){  # Run non-interactively, just send the commands, spew the returns and quit.
        execute($initial_heap,\@commands);
    }
    else {                  # Run interactively. Fire up the POE, define it's events and run the kernel!
        create_session($initial_heap);
        POE::Kernel->run;
    }
}
sub create_session {            # Create the session with all it's events
    my $starting_heap = shift;
    return POE::Session->create(
        inline_states => {
            # Ductwork
            _default        => \&_default,
            _stop           => \&_stop,
            _start          => \&_start,

            # Console-related
            prepare_console => \&prepare_console,
            got_user_input  => \&handle_user_input,
            message         => \&message,
            verbose         => \&verbose,

            # Log-related
            prepare_log     => \&prepare_log,
            write_log       => \&write_log,

            # Socket-related
            connect                 => \&connect,
            check_events            => \&check_events,
            socket_event            => \&socket_event,
            send_auth               => \&send_auth,
            send_data               => \&send_data,
            on_remote_data          => \&on_remote_data,
            on_remote_fail          => \&on_remote_fail,
            request_chat            => \&request_chat,
            request_playerlist      => \&request_playerlist,

            # Displaying data
            update_playerlist_state => \&update_playerlist_state,
            show_chat               => \&show_chat
        },
        heap => $starting_heap,
        #args => [$address,$port,$password,$verbose],
    );
}

# POE plumbing
sub _start {                    # Called when POE is spinning up
    #my ($kernel,$heap,$address,$port,$password,$verbose) = @_[KERNEL,HEAP];
    my ($kernel,$heap) = @_[KERNEL,HEAP];

    # Split the different parts into different events
    $kernel->yield('prepare_log');
    $kernel->yield('prepare_console');
    $kernel->yield(verbose => 'Verbosity is ENABLED');
    $kernel->yield('connect');
}
sub _stop {                     # For end-of-task
    my ($kernel,$heap) = @_[KERNEL,HEAP];
    delete $heap->{'tcp'};
    if (defined $heap->{'console'}){
        $heap->{'console'}->put('Bye!'); # VIOLATES poeness! OH NOES! :-P
        delete $heap->{'console'};
    }
    if (defined $heap->{'log'}){
        $heap->{'log'}->put('Log closed on '.localtime);
        $heap->{'log'}->flush;
        delete $heap->{'log'};
        delete $heap->{'log_filehandle'};
    }
}
sub _default {                  # For when I make mistakes
    my ($kernel,$heap,$event,$args) = @_[KERNEL,HEAP,ARG0,ARG1];
    my @quoted_args;
    for (@$args){
        push @quoted_args,'"'.$_.'"';
    }
    warn "\r\nSession ".$_[SESSION]->ID." wants $event(".join(', ',@quoted_args)."), but I have no idea what to do!\r\n";
}

# Console events
sub prepare_console {           # Prepare readline wheel and all that jazz
    my ($kernel,$heap) = @_[KERNEL,HEAP];
    $heap->{'console'} = POE::Wheel::ReadLine->new(
        InputEvent => 'got_user_input',
    );
    $heap->{'console'}->read_history($ENV{'HOME'}."/.ark_rcon_history");
}
sub handle_user_input {         # Triggered when the console wheel gets a line of input, mostly dispatching that input to the socket.
    my ($kernel,$heap,$input,$exception) = @_[KERNEL,HEAP,ARG0,ARG1];
    my $console = $heap->{'console'};
    if (defined $input){
        $kernel->yield(verbose => prompt($heap->{'request_count'}+1).$input);
        $console->addhistory($input);

        if ($heap->{'authed'}){
            if ($input =~ s/^!//){
                $kernel->yield(send_data => COMMAND,'serverchat '.$input);
            }
            elsif ($input eq '?'){
                my $elapsed = sprintf("%.2f",(time - $heap->{'last_event_time'}));
                $kernel->yield(message => "Last data from server seen $elapsed seconds ago: ".$heap->{'last_event_type'});
                $kernel->yield(message => scalar(keys %{$heap->{'players'}}).' players online');
                for my $player (keys %{$heap->{'players'}}){
                    $kernel->yield(message => $player.' ['.$heap->{'players'}->{$player}.']');
                }
            }
            else {
                $kernel->yield(send_data => COMMAND,$input);
            }
            $heap->{'console'}->get(prompt($heap->{'request_count'}+2));
        }
        else {
            $kernel->yield(message => 'Not authed. Connection drop?');
        }
    }
    else {
        $console->put("$exception caught.") unless $exception eq 'eot';
        $kernel->signal($kernel,'UIDESTROY');
        $console->write_history($ENV{'HOME'}."/.ark_rcon_history");
        $kernel->signal($kernel,'shutdown');
    }
}
sub verbose {                   # Pass a message on to ->message *if* verbosity is enabled
    my ($kernel,$heap,$caller_state,$message) = @_[KERNEL,HEAP,CALLER_STATE,ARG0];
    if ($heap->{'verbose'}){
        $kernel->yield(message => "[$caller_state] $message");
    }
    elsif ($heap->{'log_verbose'}){
        $kernel->yield(write_log => "[$caller_state] $message");
    }
}
sub message {                   # Output a passed message to the console, prefixed by a timestamp.
    my ($kernel,$heap,$message) = @_[KERNEL,HEAP,ARG0];
    $heap->{'console'}->put('['.timestamp()."] $message");
    $kernel->yield(write_log => $message);
}

# Log events
sub prepare_log {               # Start up logging, if enabled
    my ($kernel,$heap) = @_[KERNEL,HEAP];
    if (defined $heap->{'log'}){
        delete $heap->{'log'};
    }
    if (defined $heap->{'log_filehandle'}){
        delete $heap->{'log_filehandle'};
    }
    if ($heap->{'log_enabled'}){
        $heap->{'log_filehandle'} = IO::File->new($heap->{'log_file'},$heap->{'log_clobber'} ? 'w' : 'a') or die 'Failed to open logfile '.$heap->{'log_file'}.": $!\n";
        $heap->{'log'} = POE::Wheel::ReadWrite->new(
            Handle => $heap->{'log_filehandle'},
        );
        $heap->{'log'}->put('Logging to '.$heap->{'log_file'}.' started at '.localtime);
    }
}
sub write_log {                 # Actually write stuff to the log file
    my ($kernel,$heap,$message) = @_[KERNEL,HEAP,ARG0];
    if (defined $heap->{'log'} && $heap->{'log_enabled'}){
        $heap->{'log'}->put('['.timestamp()."] $message");
    }
}

# Socket events
sub connect {                   # Actually initiate connection, but do so in a way that will
    my ($kernel,$heap,$socket) = @_[KERNEL,HEAP,ARG0];

    my $address     = $heap->{'address'};
    my $port        = $heap->{'port'};
    my $password    = $heap->{'password'};

    $kernel->yield('socket_event','Connecting');   # Connecting counts as an event on the socket.
    $heap->{'authed'} = 0;                  # Just connecting, we can't possibly be authed.
    $heap->{'players'} = {};                # We have no idea who is on the server, obviouly.
    $heap->{'request_count'} = 0;           # No requests have been sent yet, right?
    $heap->{'players_listed'} = 0;          # Holds if the player list is an initial one, or if we just connected.

    $kernel->yield(message => "Connecting to $address:$port...");
    if (defined $socket and ref($socket) eq 'IO::Socket::INET'){
        close $socket;
    }
    
    if (defined $heap->{'tcp'}){
        $kernel->yield(verbose => 'Shutting down socket ReadWrite wheel');
        $heap->{'tcp'}->shutdown_input;
        $heap->{'tcp'}->shutdown_output;
        delete $heap->{'tcp'};
    }

    if (defined $heap->{'socket'}){
        $kernel->yield(verbose => 'Disconnecting the socket');
        close $heap->{'socket'};
        delete $heap->{'socket'};
    }

    $kernel->yield(verbose => 'Connecting');
    $heap->{'socket'} = IO::Socket::INET->new(
        PeerHost    => $address,
        PeerPort    => $port,
    ) or do {
        if (defined $heap->{'console'}){
            $kernel->yield(message => "Failed to connect: $!");
            exit 1;
        }
        else {
            die "Failed to connect: $!";
        }
    };

    $kernel->yield(verbose => 'Spinning up socket ReadWrite wheel');
    $heap->{'tcp'} = POE::Wheel::ReadWrite->new(
        Handle      => $heap->{'socket'},
        InputEvent  => 'on_remote_data',
        ErrorEvent  => 'on_remote_fail',
        Filter      => POE::Filter::Stream->new(),
    );
    $kernel->delay(send_auth => 1);
}
sub send_data {                 # Send data to the socket
    my ($kernel,$heap,$type,$payload,$id) = @_[KERNEL,HEAP,ARG0..ARG2];
    if (!defined $id or $id !~ /^[0-9]+$/){
        $id = ++$heap->{'request_count'};
        if ($heap->{'request_count'} >= ID_MAX){
            $heap->{'request_count'} = 0;
        }
    }
    my $packet = encode($type,$payload,$id);
    $kernel->yield(verbose => "Sending type $type data, ID $id: $payload");
    $heap->{'tcp'}->put($packet);
}
sub send_auth {                 # Send the AUTH packet. Shorthand for $kernel->yield(send_data => PASSWORD,$heap->{'password'},ID_PASSWORD);
        my ($kernel,$heap) = @_[KERNEL,HEAP];
        $kernel->yield(verbose => 'Authenticating...');
        $kernel->yield(send_data => PASSWORD,$heap->{'password'},ID_PASSWORD);
}
sub request_chat {              # Request more chat - Once done, calls itself every DELAY_GETCHAT seconds!
    my ($kernel,$heap) = @_[KERNEL,HEAP];
    if ($heap->{'authed'}){
        $kernel->yield(send_data => COMMAND,'getchat',ID_CHAT);
    }
    $kernel->delay(request_chat => DELAY_GETCHAT);
}
sub request_playerlist {        # Request the list of players - Once done, calls itself every DELAY_PLAYERLIST seconds!
    my ($kernel,$heap) = @_[KERNEL,HEAP];
    if ($heap->{'authed'}){
        $kernel->yield(send_data => COMMAND,'listplayers',ID_PLAYERS);
    }
    $kernel->delay(request_playerlist => DELAY_PLAYERLIST);
}
sub on_remote_data {            # Triggered when the Socket/IO Wheel gets data
    my ($kernel,$heap,$data) = @_[KERNEL,HEAP,ARG0];

    my ($size,$id,$type,$payload) = decode($data);
    $kernel->yield('socket_event',"$size bytes of type $type data, ID $id"); # There was an event at the socket!
    if ($type == 2){
        if ($id == ID_PASSWORD){
            $heap->{'authed'} = 1;
            $kernel->yield(message => "Authenticated. Go ahead.");
            $heap->{'console'}->get(prompt($heap->{'request_count'}+1));
            $kernel->delay(request_chat => 2);
            $kernel->yield('request_playerlist');
        }
        else {
            $kernel->yield(message => "Authentication failed! Bailing out!");
            $kernel->signal($kernel,'UIDESTROY');
            $kernel->signal($kernel,'shutdown');
        }
    }
    else {
        $payload =~ s/\r//g;
        my @lines = split /\n/,$payload;
        
        if ($id == ID_PLAYERS){
            $kernel->yield(update_playerlist_state => \@lines);
        }
        elsif ($id == ID_CHAT){
            $kernel->yield(show_chat => \@lines);
        }
        else {
            for my $line (@lines){
                if ($line eq NO_RESPONSE){                        
                    $kernel->yield(verbose => "$id) (the server offered no response)");
                }
                else {
                    $kernel->yield(message => "$id) $line") if $line and $line !~ /^\s+$/;
                }
            }
        }
    }
}
sub on_remote_fail {            # Called whenever an error occurs on the connection. Triggers a reconnect.
    # FIXME # possibly massively broken :-O
    my ($kernel,$heap,$type,$error_number,$error_string) = @_[KERNEL,HEAP,ARG0..ARG2];
    if ($error_number == 0){
        if ($heap->{'authed'}){
            $kernel->yield(message => 'Disconnected');
        }
        else {
            $kernel->yield(message => 'Disconnected. Wrong password?');
        }
    }
    else {
        $kernel->yield(message => "ERROR $error_number ($error_string) during $type operation.");
    }
    $kernel->yield('connect') if $heap->{'authed'}; # If we failed before we could even auth, there is really no need to try again.
}
sub socket_event {              # Simply make a note that there was an event at the socket. DO NOT CALL ON OUTGOING EVENTS!
    my ($kernel,$heap,$type) = @_[KERNEL,HEAP,ARG0];
    $type = 'UNKNOWN' unless defined $type;
    $kernel->yield(verbose => $type);
    $heap->{'last_event_time'} = time;
    $heap->{'last_event_type'} = $type;
    $kernel->delay(check_events => SOCKET_TIMEOUT_CHECK);
}
sub check_events {              # Make sure there has been socket activity in the last SOCKET_TIMEOUT seconds, or reconnect. Once called, it self-calls every SOCKET_TIMEOUT_CHECK seconds.
    my ($kernel,$heap) = @_[KERNEL,HEAP];
    if ($heap->{'last_event_time'} < (time - SOCKET_TIMEOUT)){
        $kernel->yield(message => 'No events for '.SOCKET_TIMEOUT.' seconds. Reconnecting!');
        $kernel->yield('connect');
    }
    $kernel->delay('check_events' => SOCKET_TIMEOUT_CHECK);
}

# Information management/output
sub show_chat {                 # Called whenever a packet bearing the ID_CHAT ID is recieved.
    my ($kernel,$heap,$lines) = @_[KERNEL,HEAP,ARG0];
    for my $line (@$lines){
        if ($line eq NO_RESPONSE){
            $kernel->yield(verbose => 'No new chat lines');
        }
        else {
            $kernel->yield(message => $line);
        }
    }
}
sub update_playerlist_state {   # Called whenever a packet bearing the ID_PLAYERS ID is recieved.
    my ($kernel,$heap,$lines) = @_[KERNEL,HEAP,ARG0];
    my $player_names = {};
    for my $line (@$lines){
        next if $line eq '';
        if ($line =~ /^[0-9]+\. ([^,]+), ([0-9]+)$/){
            my ($player_name,$steam_id) = ($1,$2);
            $player_names->{$player_name} = $steam_id;
        }
        elsif ($line eq 'No Players Connected'){
            for my $player (keys %{$heap->{'players'}}){
                $kernel->yield(message => "$player quit the game.");
            }
            $heap->{'players'} = {};
        }
        else {
            $kernel->yield(verbose => 'Junk while parsing user list: '.$line);
        }
    }

    my ($quit,$joined) = update_players($heap->{'players'},$player_names);

    my $changes = 0;
    for my $quit_name (@$quit){
        $changes++;
        $kernel->yield(message => "$quit_name quit the game.");
    }
    if ($heap->{'players_listed'}){
        for my $join_name (@$joined){
            $kernel->yield(message => "$join_name joined the game.");
            $changes++;
        }
    }
    else {
        if (scalar @$joined){
            my $players = join(", ",@$joined);
            $kernel->yield(message => "Connected players: $players");
            $changes = scalar @$joined;
        }
        else {
            $kernel->yield(message => "No players are connected.");
        }
        $heap->{'players_listed'} = 1;
    }
    $kernel->yield(verbose => "$changes player state changes");
}

# Non-POE
sub execute {                   # Execute commands non-interactively
    my ($heap,$commands) = @_;
    my $LOG;
    if ($heap->{'quiet'} and $heap->{'verbose'}){
        die "Can't be both --quiet AND --verbose. Perhaps you want --log-verbose? Seek --help\n";
    }
    if ($heap->{'log_enabled'}){
        $LOG = IO::File->new($heap->{'log_file'},($heap->{'log_clobber'} ? 'w' : 'a'));
        print $LOG 'Logging COMMAND MODE started at '.localtime."\n";
    }
    my $SOCKET = IO::Socket::INET->new(
        PeerHost => $heap->{'address'},
        PeerPort => $heap->{'port'},
    ) or die "Failed to connect: $!\n";

    print $SOCKET encode(PASSWORD,$heap->{'password'},ID_PASSWORD);
    my $buffer;
    recv($SOCKET,$buffer,RECV_LENGTH,0);
    my ($size,$id,$type,$payload) = decode($buffer);
    if ($type == 2){

        if ($id != ID_PASSWORD){
            die "Authentication failed!\n";
        }

        my $commandID = 0;
        for my $command (@$commands){
            $commandID++;
            $buffer = ''; # Reset buffer;
            if ($LOG && ($heap->{'verbose'} || $heap->{'log_verbose'})){
                print $LOG "$commandID> $command\n";
            }
            say "$commandID> $command" if $heap->{'verbose'};
            print $SOCKET encode(COMMAND,$command,$commandID);
            while(defined(recv($SOCKET,$buffer,RECV_LENGTH,0))){
                my ($size,$id,$type,$payload) = decode($buffer);

                $payload =~ s/\r//g;
                my @lines = split(/\n/,$payload);
                for my $line (@lines){
                    next if $line eq '';

                    if ($heap->{'verbose'}){
                        say "$id< $line";
                    }
                    elsif (not $heap->{'quiet'}){
                        say $line;
                    }

                    if ($LOG){
                        if ($heap->{'log_verbose'}){
                            print $LOG "$id< $line\n";
                        }
                        else {
                            print $LOG "$line\n";
                        }
                    }
                }
                if ($id == $commandID){
                    last; # We're not likely to get multiple packets per command.
                }
            }
        }

        close $SOCKET;
        if ($LOG){
            print $LOG 'Logging COMMAND MODE ended at '.localtime."\n";
            close $LOG;
        }
    }
    else {
        close $SOCKET;
        die "Authentication failed!\n";
    }
}
sub update_players {            # Called to update the $players hashref
    my ($players,$names) = @_;
    my $joined = [];
    my $quit = [];

    for my $name (keys %$players){
        if (defined $names->{$name}){
            delete $names->{$name};
        }
        else {
            delete $players->{$name};
            push @$quit,$name;
        }
    }
    for my $name (keys %$names){
        push @$joined,$name;
        $players->{$name} = $names->{$name};
    }
    return ($quit,$joined);
}
sub encode {                    # Used to encode an RCON packet, needs type and payload, optionally takes an ID (or uses 404, because I'm so damn funny)
    my ($type,$payload,$id) = @_;
    $payload = '' unless defined $payload;
    $id = 404 unless defined $id;
    my $data = pack("II",$id,$type);
    $data .= $payload.chr(0).chr(0);
    $data = pack("I",length($data)).$data;
    return $data;
}
sub decode {                    # Used to take input from the socket and turn it into ($size,$id,$tye,$payload) or just $payload if you don't want an array
    my $raw_packet = shift;
    if (length($raw_packet) >= 8){ # Checking if the packet is even CLOSE to viable...
        my $size    = unpack("I",substr($raw_packet,0,4));
        my $id      = unpack("I",substr($raw_packet,4,4));
        my $type    = unpack("I",substr($raw_packet,8,4));
        my $payload = substr($raw_packet,12,$size-13); #-13 are the 12 leading chrs and strips off the end-of-message \0
        if (wantarray){
           return ($size,$id,$type,$payload);
        }
        else {
            return $payload;
        }
    }
    else {
        warn "Invalid packet came in, only ".length($raw_packet)." characters long!\n";
        return (0,0,0,'');
    }
}
sub prompt {                    # Used to generate a prompt string
    my $id = shift;
    $id = '?' unless defined $id;
    return "CMD $id> ";
}
sub timestamp {                 # Used to get a nice looking timestamp for the given UNIX time in [HH:MM:SS] format. Optionally give the UNIX time, or let it use the current time.
    my $time = shift;
    $time = time unless $time;
    my ($sec,$min,$hour) = localtime($time);
    return sprintf("%02s:%02s:%02s",$hour,$min,$sec);
}
sub help_table {                # Output a usage help table to STDOUT
    #TODO# This is *very* crude, but it's elegance is not really required.
    say "ark_rcon.pl v$VERSION command line options:\n";

    for my $option (@OPTIONS_ORDER){
        if ($option =~ s/^!//){
            say $option,"\n";
        }
        else {
            say "--$option";
            my @lines = @{$OPTIONS_DOC{$option}};
            for my $line (@lines){
                say "    $line";
            }
            print "\n";
        }
    }
}

