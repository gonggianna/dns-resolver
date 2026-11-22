
import socket
import sys
import struct


def parse_header(data):
	if len(data) < 12:
		raise ValueError("DNS packet too short")

	header = struct.unpack("!HHHHHH", data[:12])

	transaction_id, flags, qdcount, ancount, nscount, arcount = header

	print(f"Transaction ID: {transaction_id}")
	print(f"Flags: {flags:016b}")
	print(f"Questions: {qdcount}")
	print(f"Answers: {ancount}")
	print(f"Authority records: {nscount}")
	print(f"Additional records: {arcount}")


def parse_question(data):
	offset = 12
	labels = []

	while True:
		if offset >= len(data):
			raise ValueError("Incomplete DNS name")

		length = data[offset]
		offset += 1

		if length == 0:
			break

		if length > 63:
			raise ValueError("Invalid DNS label length")

		if offset + length > len(data):
			raise ValueError("Truncated DNS label")

		label = data[offset:offset + length].decode("ascii")
		labels.append(label)

		offset += length

	if offset + 4 > len(data):
		raise ValueError("Incomplete DNS question")

	qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])

	domain = ".".join(labels)

	print(f"Domain: {domain}")
	print(f"Query type: {qtype}")
	print(f"Query class: {qclass}")

	return domain, qtype, qclass


def build_response(data):
	transaction_id, flags, qdcount, _, _, _ = struct.unpack(
		"!HHHHHH", data[:12]
	)

	# QR=1, AA=1 (for this test only), preserve RD
	response_flags = 0x8400 | (flags & 0x0100)

	offset = 12

	while data[offset] != 0:
		offset += data[offset] + 1

	offset += 1
	question_end = offset + 4

	question = data[12:question_end]

	# Pointer to question name at offset 12
	name = b"\xc0\x0c"

	# TYPE=A, CLASS=IN, TTL=60, RDLENGTH=4
	record = struct.pack("!HHIH", 1, 1, 60, 4)

	# Fixed test IP address
	ip_address = socket.inet_aton("1.2.3.4")

	answer = name + record + ip_address

	header = struct.pack(
		"!HHHHHH",
		transaction_id,
		response_flags,
		1,
		1,
		0,
		0
	)

	return header + question + answer

def query_upstream(data):
	upstream = ("8.8.8.8", 53)

	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
		upstream_sock.settimeout(3)
		upstream_sock.sendto(data, upstream)

		response, address = upstream_sock.recvfrom(4096)

		if address != upstream:
			raise ValueError("Unexpected upstream DNS server")

		return response

def main():
	port = int(sys.argv[1]) if len(sys.argv) > 1 else 53

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind(("0.0.0.0", port))

	print(f"DNS resolver listening on UDP port {port}", flush=True)

	while True:
		data, address = sock.recvfrom(4096)

		print(f"\nReceived {len(data)} bytes from {address}")
		print(f"Raw packet: {data.hex()}")

		try:
			parse_header(data)
			domain, qtype, qclass = parse_question(data)

			response = query_upstream(data)
			sock.sendto(response, address)
			print(f"Forwarded real DNS response for {domain}")

		except (ValueError, IndexError, UnicodeError, struct.error, socket.timeout, OSError) as e:
			print(f"Invalid DNS packet: {e}")


if __name__ == "__main__":
	try:
		 main()
	except KeyboardInterrupt:
		print("\nDNS resolver stopped.")
	

