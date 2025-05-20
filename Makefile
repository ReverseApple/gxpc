all:
	cd ./script && npm install
	cd ./script && ./node_modules/.bin/frida-compile -S -c ./script.ts -o ../_agent.js
	go build
