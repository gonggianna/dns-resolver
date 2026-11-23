import secrets
import socket
import struct
import sys
import time

ROOT_SERVERS = ["198.41.0.4", "199.9.14.201"]
MAX_REFERRALS = 12
MAX_NS_DEPTH = 4
DNS_CACHE = {}


def read_name(data, offset):
	labels = []
	end_offset = None
	visited = set()
	wire_length = 1

	while True:
		if offset >= len(data) or offset in visited:
			raise ValueError("Invalid DNS name or compression loop")
		visited.add(offset)
		length = data[offset]

		if length & 0xC0 == 0xC0:
			if offset + 1 >= len(data):
				raise ValueError("Truncated compression pointer")
			pointer = ((length & 0x3F) << 8) | data[offset + 1]
			if pointer >= offset:
				raise ValueError("Invalid compression pointer")
			if end_offset is None:
				end_offset = offset + 2
			offset = pointer
			continue

		if length & 0xC0 or length > 63:
			raise ValueError("Invalid DNS label length")
		offset += 1
		if length == 0:
			break
		if offset + length > len(data):
			raise ValueError("Truncated DNS label")
		wire_length += length + 1
		if wire_length > 255:
			raise ValueError("DNS name exceeds 255 bytes")
		labels.append(data[offset:offset + length].decode("ascii"))
		offset += length

	return ".".join(labels), end_offset if end_offset is not None else offset


def parse_question(data):
	if len(data) < 12:
		raise ValueError("DNS header too short")
	_, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
	if flags & 0x8000 or (flags & 0x7800) or qd != 1 or an or ns:
		raise ValueError("Not a supported DNS query")
	name, offset = read_name(data, 12)
	if offset + 4 > len(data):
		raise ValueError("Truncated DNS question")
	qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
	return name, qtype, qclass


def parse_record(data, offset):
	name, offset = read_name(data, offset)
	if offset + 10 > len(data):
		raise ValueError("Truncated DNS record")
	rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
	ttl_offset = offset + 4
	offset += 10
	rdata_offset = offset
	if offset + rdlength > len(data):
		raise ValueError("Truncated DNS record data")
	rdata = data[offset:offset + rdlength]
	offset += rdlength
	record = {"name": name, "type": rtype, "class": rclass,
		"ttl": ttl, "ttl_offset": ttl_offset, "rdata": rdata}
	if rtype == 1 and rdlength == 4:
		record["address"] = socket.inet_ntoa(rdata)
	elif rtype in (2, 5):
		target, target_end = read_name(data, rdata_offset)
		if target_end != rdata_offset + rdlength:
			raise ValueError("Invalid domain-name RDATA")
		record["target"] = target
	return record, offset


def parse_dns_response(data):
	if len(data) < 12:
		raise ValueError("Truncated DNS header")
	transaction, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
	offset = 12
	for _ in range(qd):
		_, offset = read_name(data, offset)
		if offset + 4 > len(data):
			raise ValueError("Truncated DNS question")
		offset += 4
	sections = {}
	for label, count in (("answers", an), ("authority", ns), ("additional", ar)):
		section = []
		for _ in range(count):
			record, offset = parse_record(data, offset)
			section.append(record)
		sections[label] = section
	if offset != len(data):
		raise ValueError("Trailing DNS bytes")
	return sections


def encode_name(name):
	if not name:
		return b"\x00"
	result = bytearray()
	for label in name.rstrip(".").split("."):
		part = label.encode("ascii")
		if not (1 <= len(part) <= 63):
			raise ValueError("Invalid DNS label")
		result.append(len(part))
		result.extend(part)
	result.append(0)
	if len(result) > 255:
		raise ValueError("DNS name too long")
	return bytes(result)


def make_a_query(name, qclass=1):
	transaction = secrets.randbits(16)
	header = struct.pack("!HHHHHH", transaction, 0, 1, 0, 0, 1)
	question = encode_name(name) + struct.pack("!HH", 1, qclass)
	opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)
	return header + question + opt


def send_query(query, server_ip):
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
		sock.settimeout(2)
		sock.sendto(query, (server_ip, 53))
		while True:
			response, address = sock.recvfrom(4096)
			if address != (server_ip, 53) or len(response) < 12:
				continue
			if response[:2] != query[:2]:
				continue
			flags = struct.unpack("!H", response[2:4])[0]
			if not (flags & 0x8000):
				continue
			if flags & 0x0200:
				raise ValueError("Truncated upstream UDP response")
			return response


def unique(items):
	return list(dict.fromkeys(items))


def get_referral_ips(sections, depth, active):
	ns_records = [r for r in sections["authority"] if r["type"] == 2 and "target" in r]
	ns_names = {r["target"].lower() for r in ns_records}
	if not ns_names:
		return []
	glue = [r["address"] for r in sections["additional"]
		if r["type"] == 1 and r["class"] == 1
		and "address" in r and r["name"].lower() in ns_names]
	if glue:
		return unique(glue)

	# No glue: perform an independent iterative lookup of a nameserver's A record.
	if depth >= MAX_NS_DEPTH:
		return []
	resolved = []
	for ns_name in list(ns_names)[:4]:
		if ns_name in active:
			continue
		print(f"  No glue; resolving nameserver {ns_name}")
		try:
			query = make_a_query(ns_name)
			ns_response = iterative_resolve(query, depth + 1, active | {ns_name})
			ns_sections = parse_dns_response(ns_response)
			resolved.extend(r["address"] for r in ns_sections["answers"]
				if r["type"] == 1 and r["class"] == 1 and
				"address" in r and r["name"].lower() == ns_name)
		except (ValueError, OSError, TimeoutError) as error:
			print(f"  Could not resolve {ns_name}: {error}")
	return unique(resolved)


def iterative_resolve(request, depth=0, active=None):
	if active is None:
		active = set()
	if depth > MAX_NS_DEPTH:
		raise ValueError("Nameserver lookup depth exceeded")
	if len(request) < 12:
		raise ValueError("Truncated DNS query")
	flags = struct.unpack("!H", request[2:4])[0] & ~0x0100
	query = request[:2] + struct.pack("!H", flags) + request[4:]
	servers = ROOT_SERVERS[:]
	visited = set()

	for hop in range(MAX_REFERRALS):
		next_servers = None
		for server_ip in servers:
			if server_ip in visited:
				continue
			visited.add(server_ip)
			print(f"  Hop {hop + 1}: querying {server_ip}")
			try:
				response = send_query(query, server_ip)
				sections = parse_dns_response(response)
			except (ValueError, OSError, TimeoutError) as error:
				print(f"  Server {server_ip} failed: {error}")
				continue

			response_flags = struct.unpack("!H", response[2:4])[0]
			rcode = response_flags & 0x000F
			if rcode == 3 or sections["answers"] or (response_flags & 0x0400):
				return response
			if rcode != 0:
				continue

			next_servers = get_referral_ips(sections, depth, active)
			if next_servers:
				print(f"  Referral: {len(next_servers)} IPv4 server(s) available")
				break

		if not next_servers:
			raise ValueError("No responding DNS server or usable referral")
		servers = next_servers

	raise ValueError("Maximum DNS referral count exceeded")


def cache_key(request):
	# Include question and EDNS options, avoiding mismatched cached wire formats.
	return request[12:]


def get_cached_response(request):
	key = cache_key(request)
	entry = DNS_CACHE.get(key)
	if entry is None:
		print("Cache MISS")
		return None
	now = time.monotonic()
	if now >= entry["expires"]:
		del DNS_CACHE[key]
		print("Cache EXPIRED")
		return None
	elapsed = now - entry["stored"]
	response = bytearray(entry["response"])
	for offset, initial_ttl in entry["ttls"]:
		struct.pack_into("!I", response, offset, max(0, int(initial_ttl - elapsed)))
	response[:2] = request[:2]
	print(f"Cache HIT ({entry['expires'] - now:.1f}s remaining)")
	return bytes(response)


def cache_response(request, response):
	flags = struct.unpack("!H", response[2:4])[0]
	if flags & 0x000F or flags & 0x0200:
		return
	sections = parse_dns_response(response)
	if not sections["answers"]:
		return
	records = [r for section in sections.values() for r in section if r["type"] != 41]
	if not records:
		return
	ttl = min(r["ttl"] for r in records)
	if ttl <= 0:
		return
	now = time.monotonic()
	DNS_CACHE[cache_key(request)] = {
		"response": response, "stored": now, "expires": now + ttl,
		"ttls": [(r["ttl_offset"], r["ttl"]) for r in records]
	}
	print(f"Cached response for {ttl}s")


def prepare_client_response(response, request):
	packet = bytearray(response)
	packet[:2] = request[:2]
	upstream_flags = struct.unpack("!H", packet[2:4])[0]
	request_flags = struct.unpack("!H", request[2:4])[0]
	# QR=1, RA=1; AA=0 because our resolver is not authoritative.
	upstream_flags = (upstream_flags | 0x8080) & ~0x0500
	upstream_flags |= (request_flags & 0x0100)
	struct.pack_into("!H", packet, 2, upstream_flags)
	return bytes(packet)


def main():
	port = int(sys.argv[1]) if len(sys.argv) > 1 else 53
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
		server.bind(("0.0.0.0", port))
		print(f"DNS resolver listening on UDP port {port}", flush=True)
		while True:
			request, client = server.recvfrom(4096)
			try:
				name, qtype, qclass = parse_question(request)
				print(f"\nRequest: {name} TYPE={qtype} CLASS={qclass}")
				response = get_cached_response(request)
				if response is None:
					response = iterative_resolve(request)
					cache_response(request, response)
				response = prepare_client_response(response, request)
				server.sendto(response, client)
			except (ValueError, UnicodeError, struct.error, OSError) as error:
				print(f"Dropped/failed query: {error}")


if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		print("\nDNS resolver stopped")

