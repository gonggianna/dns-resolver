import time
import socket
import struct
import sys

DNS_CACHE = {}
ROOT_SERVER = ("198.41.0.4", 53)
MAX_REFERRALS = 10


# --------------------------------------------------
# DNS HEADER
# --------------------------------------------------

def parse_header(data):
	if len(data) < 12:
		raise ValueError("DNS packet too short")

	transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
		"!HHHHHH", data[:12]
	)

	print(f"Transaction ID: {transaction_id}")
	print(f"Flags: {flags:016b}")
	print(f"Questions: {qdcount}")
	print(f"Answers: {ancount}")
	print(f"Authority records: {nscount}")
	print(f"Additional records: {arcount}")

	return transaction_id, flags, qdcount, ancount, nscount, arcount


# --------------------------------------------------
# DNS NAME DECODING
# --------------------------------------------------

def read_name(data, offset):
	labels = []
	end_offset = None
	visited = set()
	total_length = 1

	while True:
		if offset >= len(data):
			raise ValueError("DNS name extends beyond packet")

		if offset in visited:
			raise ValueError("DNS compression pointer loop")

		visited.add(offset)
		length = data[offset]

		if length & 0xC0 == 0xC0:
			if offset + 1 >= len(data):
				raise ValueError("Truncated compression pointer")

			pointer = ((length & 0x3F) << 8) | data[offset + 1]

			if pointer >= offset:
				raise ValueError("Invalid DNS compression pointer")

			if end_offset is None:
				end_offset = offset + 2

			offset = pointer
			continue

		if length & 0xC0:
			raise ValueError("Invalid DNS label encoding")

		offset += 1

		if length == 0:
			break

		if offset + length > len(data):
			raise ValueError("Truncated DNS label")

		total_length += length + 1

		if total_length > 255:
			raise ValueError("DNS name exceeds 255 bytes")

		labels.append(data[offset:offset + length].decode("ascii"))
		offset += length

	return ".".join(labels), end_offset if end_offset is not None else offset


# --------------------------------------------------
# DNS QUESTION
# --------------------------------------------------

def parse_question(data):
	domain, offset = read_name(data, 12)

	if offset + 4 > len(data):
		raise ValueError("Incomplete DNS question")

	qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])

	print(f"Domain: {domain}")
	print(f"Query type: {qtype}")
	print(f"Query class: {qclass}")

	return domain, qtype, qclass


# --------------------------------------------------
# DNS RESOURCE RECORD
# --------------------------------------------------

def parse_record(data, offset):
	name, offset = read_name(data, offset)

	if offset + 10 > len(data):
		raise ValueError("Truncated DNS resource record")

	rtype, rclass, ttl, rdlength = struct.unpack(
		"!HHIH", data[offset:offset + 10]
	)

	offset += 10
	rdata_offset = offset

	if offset + rdlength > len(data):
		raise ValueError("Truncated DNS record data")

	rdata = data[offset:offset + rdlength]
	offset += rdlength

	record = {
		"name": name,
		"type": rtype,
		"class": rclass,
		"ttl": ttl,
		"rdata": rdata
	}

	if rtype == 1 and rdlength == 4:
		record["address"] = socket.inet_ntoa(rdata)

	elif rtype == 2:
		ns_name, ns_end = read_name(data, rdata_offset)

		if ns_end != rdata_offset + rdlength:
			raise ValueError("Invalid NS record")

		record["ns"] = ns_name

	return record, offset


# --------------------------------------------------
# PARSE DNS RESPONSE SECTIONS
# --------------------------------------------------

def parse_dns_response(data):
	if len(data) < 12:
		raise ValueError("Truncated DNS response")

	_, _, qdcount, ancount, nscount, arcount = struct.unpack(
		"!HHHHHH", data[:12]
	)

	offset = 12

	for _ in range(qdcount):
		_, offset = read_name(data, offset)

		if offset + 4 > len(data):
			raise ValueError("Truncated DNS question")

		offset += 4

	sections = {}

	for section, count in [
		("answers", ancount),
		("authority", nscount),
		("additional", arcount)
	]:
		records = []

		for _ in range(count):
			record, offset = parse_record(data, offset)
			records.append(record)

		sections[section] = records

	if offset != len(data):
		raise ValueError("Unexpected trailing DNS data")

	return sections


# --------------------------------------------------
# FIND NEXT NAMESERVER
# --------------------------------------------------

def get_nameserver_ip(sections, visited):
	ns_names = {
		record["ns"].lower()
		for record in sections["authority"]
		if record["type"] == 2 and "ns" in record
	}

	for record in sections["additional"]:
		if (
			record["type"] == 1
			and "address" in record
			and record["name"].lower() in ns_names
			and record["address"] not in visited
		):
			return record["address"]

	return None


# --------------------------------------------------
# ITERATIVE DNS RESOLUTION
# --------------------------------------------------


def get_cached_response(domain, qtype, qclass, request):
	key = (domain.lower(), qtype, qclass)

	if key not in DNS_CACHE:
		print(f"Cache MISS: {domain}")
		return None

	entry = DNS_CACHE[key]
	now = time.monotonic()

	if now >= entry["expires"]:
		del DNS_CACHE[key]
		print(f"Cache EXPIRED: {domain}")
		return None

	remaining = entry["expires"] - now
	response = bytearray(entry["response"])

	# Update each cached record's TTL
	for ttl_offset, original_ttl in entry["ttls"]:
		new_ttl = max(0, int(original_ttl - (now - entry["stored"])))
		struct.pack_into("!I", response, ttl_offset, new_ttl)

	# Restore the client's transaction ID
	response[:2] = request[:2]

	# Preserve the client's recursion-desired flag
	flags = struct.unpack("!H", response[2:4])[0]
	request_flags = struct.unpack("!H", request[2:4])[0]

	flags = (flags & ~0x0100) | (request_flags & 0x0100)
	struct.pack_into("!H", response, 2, flags)

	print(f"Cache HIT: {domain} ({remaining:.1f}s remaining)")
	return bytes(response)


def cache_response(domain, qtype, qclass, response):
	sections = parse_dns_response(response)

	# Do not cache negative or empty answers
	flags = struct.unpack("!H", response[2:4])[0]

	if flags & 0x000F:
		return

	if not sections["answers"]:
		return

	# Cache by the shortest answer TTL
	ttl = min(record["ttl"] for record in sections["answers"])

	if ttl <= 0:
		return

	# Locate TTL fields in the original DNS message
	ttl_offsets = []
	_, _, qd, an, ns, ar = struct.unpack("!HHHHHH", response[:12])

	offset = 12

	for _ in range(qd):
		_, offset = read_name(response, offset)
		offset += 4

	for _ in range(an + ns + ar):
		_, offset = read_name(response, offset)

		if offset + 10 > len(response):
			raise ValueError("Truncated DNS record")

		rtype, rclass, record_ttl, rdlength = struct.unpack(
			"!HHIH", response[offset:offset + 10]
		)

		# OPT records use this field for EDNS flags, not TTL
		if rtype != 41:
			ttl_offsets.append((offset + 4, record_ttl))

		offset += 10 + rdlength

	now = time.monotonic()
	key = (domain.lower(), qtype, qclass)

	DNS_CACHE[key] = {
		"response": bytes(response),
		"stored": now,
		"expires": now + ttl,
		"ttls": ttl_offsets
	}

	print(f"Cached {domain} for {ttl} seconds")


def query_upstream(data):
	if len(data) < 12:
		raise ValueError("DNS query too short")

	# Disable recursion (RD = 0)
	flags = struct.unpack("!H", data[2:4])[0]
	flags &= ~0x0100

	query = data[:2] + struct.pack("!H", flags) + data[4:]

	server_ip = ROOT_SERVER[0]
	visited = set()

	for step in range(MAX_REFERRALS):
		if server_ip in visited:
			raise ValueError("DNS referral loop detected")

		visited.add(server_ip)

		print(f"\nStep {step + 1}: Querying {server_ip}")

		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
			upstream_sock.settimeout(3)
			upstream_sock.sendto(query, (server_ip, 53))

			response, address = upstream_sock.recvfrom(4096)

			if address != (server_ip, 53):
				raise ValueError("Unexpected DNS server")

		if len(response) < 12:
			raise ValueError("Truncated DNS response")

		if response[:2] != query[:2]:
			raise ValueError("DNS transaction ID mismatch")

		response_flags = struct.unpack("!H", response[2:4])[0]

		if not (response_flags & 0x8000):
			raise ValueError("Received packet is not a DNS response")

		sections = parse_dns_response(response)

		_, _, _, an, ns, ar = struct.unpack(
			"!HHHHHH", response[:12]
		)

		print(f"Answers: {an}")
		print(f"Authority records: {ns}")
		print(f"Additional records: {ar}")

		rcode = response_flags & 0x000F

		if rcode != 0:
			print(f"DNS response code: {rcode}")
			return response

		if sections["answers"]:
			print("Final DNS answer received")
			return response

		if response_flags & 0x0400:
			print("Authoritative response received")
			return response

		next_ip = get_nameserver_ip(sections, visited)

		if next_ip is None:
			raise ValueError("No usable IPv4 nameserver referral found")

		print(f"Following referral to {next_ip}")
		server_ip = next_ip

	raise ValueError("Maximum DNS referral depth exceeded")


# --------------------------------------------------
# UDP DNS SERVER
# --------------------------------------------------

def main():
	port = int(sys.argv[1]) if len(sys.argv) > 1 else 53

	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
		sock.bind(("0.0.0.0", port))

		print(f"DNS resolver listening on UDP port {port}", flush=True)

		while True:
			data, address = sock.recvfrom(4096)

			print(f"\nReceived {len(data)} bytes from {address}")

			try:
				parse_header(data)
				domain, qtype, qclass = parse_question(data)

				
				response = get_cached_response(domain, qtype, qclass, data)

				if response is None:
					response = query_upstream(data)
					cache_response(domain, qtype, qclass, response)

				sock.sendto(response, address)
				print(f"Resolved DNS query for {domain}")


			except (
				ValueError,
				IndexError,
				UnicodeError,
				struct.error,
				socket.timeout,
				OSError
			) as e:
				print(f"DNS query failed: {e}")


if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		print("\nDNS resolver stopped.")

