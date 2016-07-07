default:
	gcc code/dosuid.c -o dosuid
	chown root:root dosuid
	chmod +s dosuid
