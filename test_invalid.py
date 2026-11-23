
import socket
import struct


SERVER = ("127.0.0.1", 18240)


def send_test(name, packet):
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
		sock.settimeout(1)
		sock.sendto(packet, SERVER)

		try:
			response, _ = sock.recvfrom(4096)
			print(f"FAIL: {name} - received {len(response)} bytes")
		except socket.timeout:
			print(f"PASS: {name} - packet dropped")


header = struct.pack("!HHHHHH", 1234, 0x0100, 1, 0, 0, 0)

# Test 1: Packet shorter than the 12-byte header
send_test("Truncated header", b"\x00\x01")

# Test 2: Question contains no domain name
send_test("Missing question", header)

# Test 3: DNS label exceeds the maximum length of 63
send_test("Invalid label length", header + b"\x40" + b"a" * 64 + b"\x00\x00\x01\x00\x01")

# Test 4: Compression pointer points to itself
send_test("Compression pointer loop", header + b"\xc0\x0c\x00\x01\x00\x01")

# Test 5: Question ends before TYPE and CLASS are complete
send_test("Truncated question", header + b"\x00\x00\x01")

