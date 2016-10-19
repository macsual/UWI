#!/usr/bin/env python

import subprocess
import select
import math

def isPrime(num):
    if num == 1:
        return False

    if num == 2:
        return True

    for i in xrange(2, int(math.sqrt(num)) + 1):
        if num % i == 0:
            return False

    return True

def test_connect_to_server():
	server = subprocess.Popen("./server.py", stdin=subprocess.PIPE, stdout=subprocess.PIPE)

	writeable = select.select([], [server.stdin], [])[1] # block until server is ready for input
	for s in writeable:
		if s == server.stdin:
			server.stdin.write(str(911) + "\n" + str(61) + "\n")
			server.stdin.flush() # to ensure data is written before proceeding

	readable = select.select([server.stdout], [], [])[1] # block until server starts listening
	for s in readable:
		if s == server.stdout:
			pass

	client = subprocess.Popen("./client.py", stdin=subprocess.PIPE, stdout=subprocess.PIPE)
			
	buff = client.communicate()[0] # get client program's output

	client.wait() # block until client finishes

	server.terminate() # kill server instance

	if buff.find("Failed to establish connection to remote host") >= 0:
		print "Test Case For Client Connecting To Server | FAIL"
		return 0, 1
	else:
		print "Test Case For Client Connecting To Server | PASS"
		return 1, 1

def test_ranges():
	total_passes = 0
	num_test_cases = 0

	print "Test Cases For Prime Number Pair Inputs"
	print ""
	
	for p in xrange(907, 1014):
		if not isPrime(p):
			continue

		for q in xrange(53, 68):
			if not isPrime(q):
				continue

			# spawn new server instance to test another prime pair for key generation
			server = subprocess.Popen("./server.py", stdin=subprocess.PIPE, stdout=subprocess.PIPE)

			writeable = select.select([], [server.stdin], [])[1] # block until server is ready for input
			for s in writeable:
				if s == server.stdin:
					server.stdin.write(str(p) + "\n" + str(q) + "\n")
					server.stdin.flush() # to ensure data is written before proceeding

			readable = select.select([server.stdout], [], [])[1] # block until server starts listening
			for s in readable:
				if s == server.stdout:
					pass

			client = subprocess.Popen("./client.py", stdin=subprocess.PIPE, stdout=subprocess.PIPE)
			
			buff = client.communicate()[0] # get client program's output

			client.wait() # block until client finishes

			server.terminate() # kill server instance

			if buff.find("200 OK") >= 0:
				print "Test Case " + str(num_test_cases + 1) + ": " + "p = " + str(p) + " q = " + str(q) + " | PASS"

				total_passes += 1
				num_test_cases += 1
			else:
				print "Test Case " + str(num_test_cases + 1) + ": " + "p = " + str(p) + " q = " + str(q) + " | FAIL"

				num_test_cases += 1

	return total_passes, num_test_cases

def main():
	total_passes = 0
	total_test_cases = 0

	num_passes, num_test_cases = test_connect_to_server()
	total_passes += num_passes
	total_test_cases += num_test_cases

	print ""
	
	num_passes, num_test_cases = test_ranges()
	total_passes += num_passes
	total_test_cases += num_test_cases

	pass_percentage = (total_passes / total_test_cases) * 100
	
	print ""
	print "Passed " + str(pass_percentage) + "% (" + str(total_passes) + "/" + str(total_test_cases) + ") of test cases."

if __name__ == "__main__":
    main()
