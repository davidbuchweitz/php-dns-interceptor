<?php

/**
 * PHP DNS Interceptor
 *
 * Intercepts DNS queries to answer from local database allowing wildcard
 * lookups. By default, a file named records will be loaded in the same
 * directory where script is started from.
 *
 * Records file format is one record per line:
 * <ip address> <domain>
 *
 * Example:
 * 127.0.0.1 mydomain.local
 * 127.0.0.1 *.domain.local
 * 127.0.0.1 *something*.*.org
 *
 * Requires PHP5.6+ with sockets extension
 */

class DNSProxy
{
	# Address to bind to
	public $address = "127.0.0.1";

	# Port to bind to
	public $port = 53;

	# Path to records file
	public $path = "./records";

	# Enable debugging
	public $debug = true;

	# Hash of records file to detect changes
	private $hash = null;

	# Array to store records from file
	private $db = [];

	public function __construct()
	{
		# Ignore script timeout
		set_time_limit(0);

		# Load database
		$this->loadDB();
	}

	public function listen()
	{
		# Create new UDP socket server
		$this->socket = socket_create(AF_INET,SOCK_DGRAM, SOL_UDP);

		# Bind socket to address and port
		socket_bind($this->socket, $this->address, $this->port);

		# Listen for new queries in a loop
		while(true)
		{
			# Respond to query
			@socket_recvfrom($this->socket, $buf, 4096, 0, $peer_ip, $peer_port);

			# Check for database change
			$this->loadDB();

			# Will build up query here
			$query = "";

			# Get buffer from the 13th byte
			$tmp = substr($buf, 12);

			# Read buffer from 13th byte until we find a null
			# Parts of a domain are called labels i.e label.label.label.tld
			# The first byte of each label in our buffer is the length in bytes of the label to follow
			# e.g this.is.a.domain.com would be (4)this.(2)is.(1)a.(6)domain.(3)com
			for ($i=0; $i<strlen($tmp); $i++)
			{
				# Get ascii code of byte representing length of label (int)
				$label_len = ord($tmp[$i]);

				# Null found, end of domain
				if ($label_len == 0)
					break;

				# Append label to $query with a period
				$query .= substr($tmp, $i+1, $label_len).".";

				# Move $i to next label
				$i += $label_len;
			}

			# Remove trailing .
			$query = rtrim($query, '.');

			# Move up by two bytes
			$i+=2;

			$this->debug("Query: $query", false);

			# Perform a local lookup from db
			if ($addr = $this->lookup($query))
			{
				$this->debug(' [hit]');

				# we have a match in our DB, build up response and send
				$out  = $buf[0].$buf[1].chr(129).chr(128).$buf[4].$buf[5].$buf[4].$buf[5].chr(0).chr(0).chr(0).chr(0);
				$out .= $tmp;
				$out .= chr(192).chr(12);
				$out .= chr(0).chr(1).chr(0).chr(1).chr(0).chr(0).chr(0).chr(60).chr(0).chr(4);
				$out .= $addr;
				@socket_sendto($this->socket, $out, strlen($out), 0, $peer_ip, $peer_port);
			}
			else $this->debug(' [miss]');
		}
	}

	# Converts xxx.xxx.xxx.xxx to bytes representation for response
	private function IP2Bytes($bytes)
	{
		return implode(array_map(function($oct)
		{
			return chr($oct);
		}, explode(".", $bytes)));
	}

	# Loads records from $this->filename if $this->hash changed since last load
	private function loadDB()
	{
		if (file_exists($this->path))
		{
			if ($this->hash != ($hash = md5_file($this->path)))
			{
				$this->debug('Loading database: ', false);
				$this->hash = $hash;

				$records = file($this->path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

				$valid = 0;

				foreach ($records as $record)
				{
					if (count($fields = preg_split('/\s+/', trim($record))) < 2)
						continue;

					$valid++;

					list($address, $domain) = $fields;

					$domain = str_replace(['.', '*'], ['\.', '.+'], $domain);

					$this->db[$domain] = $this->IP2Bytes($address);
				}
				$this->debug("$valid records added.");
			}
		}
	}

	# Perform lookup in $this->db array of regex to ip records
	private function lookup($query)
	{
		foreach ($this->db as $domain => $address)
			if (preg_match('/'.$domain.'/', $query))
				return $address;

		return null;
	}

	# Log to STDOUT if $this->debug = true
	private function debug($data, $crlf=true)
	{
		if ($this->debug)
			echo $data;

		if ($crlf)
			echo "\n";
	}
}

$dp = new DNSProxy();

$dp->listen();
