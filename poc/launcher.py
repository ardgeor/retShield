import sys
import frida
from os import path


def on_message(message, data):
	print ("[{}] -> {}".format(message, data))


def instrument(target_process, path_to_script):
	session = frida.attach(target_process)
	script = None

	with open(path_to_script, "r") as fd:
		script = session.create_script(fd.read())

	script.on('message', on_message)
	script.load()
	input('Press the enter key for detaching\n\n\n')
	session.detach()


if __name__ == '__main__':
	if len(sys.argv) < 3:		
		print('Usage: {} <process name or PID> <script>'.format(__file__))
		sys.exit(1)

	try:
		target_process = int(sys.argv[1])
	except ValueError:
		print("[!] Invalid PID '%s'. Aborting..." % sys.argv[1])
		exit(1)
	
	path_script = sys.argv[2]

	if not path.isfile(path_script):
		print("[!] File '{}' does not exists. Aborting...".format(path_script))
		exit(1)

	instrument(target_process, path_script)
