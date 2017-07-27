//server
//xor
var Xorc = function(salt){
    var randomMax = 100,
    	randomMin = -100;
    
    var saltInt = parseInt(salt);
    	if ( salt ) {
        	if ( !saltInt ) {
            		throw new Error('Salt is not a Number');
        	}
        	this.salt = saltInt;
    	}
    	else {
    		this.salt = Math.round(Math.random()*(randomMax-randomMin)+randomMin);
    	}
};
Xorc.prototype.encrypt = function(str) {
    var result = '';
    for (var i=0; i<str.length; i++) {
        result += String.fromCharCode( this.salt ^ str.charCodeAt(i) );
   	}
    return result;
};
Xorc.prototype.decrypt = function(hash) {
   var result = '';
   for (var i=0; i<hash.length; i++) {
        result += String.fromCharCode( this.salt ^ hash.charCodeAt(i) );
    }
    return result;
};
//end of xor

//caesar
var caesarShift = function(str, amount){
	var buffer="";
	var code;
	for(var i=0; i<str.length; i++){
		code = str.charCodeAt(i)+amount;
		buffer=buffer+String.fromCharCode(code);
	}
	return buffer;
};
// end of caesar

var p; //modulus
var g; //base
var b; //local secret
var xor;
var sessions=[];//array of sessions
var session;

var http = require('http'); //loading http module
var fs = require('fs'); //read from filesystem
var Base64 = require('js-base64').Base64;//base 64 en- and decoding

var server = http.createServer(function(request, response){//creating server
	fs.readFile("client.html", 'utf-8', function(error, data){//loading client
		response.writeHead(200,{'Content-Type':'text/html'});
		response.write(data);
		response.end();
	});
}).listen(7000);

var io = require('socket.io').listen(server);

Array.prototype.getSession = function(id){ //getting session's id
	for(var k in this){
		if(this[k].id===id){
			return this[k];
		}
	}
};

function randomInt (min,max){ //returns a random integer between min and max
	return Math.floor(Math.random() * (max - min + 1)) + min;
}

function getPrimes(max) { //returns an array of all primes between 2 and max
    var sieve = [], i, j, primes = [];
    for (i = 2; i <= max; ++i) {
        if (!sieve[i]) {
            // i has not been marked -- it is prime
            primes.push(i);
            for (j = i << 1; j <= max; j += i) {
                sieve[j] = true;
            }
        }
    }
    return primes;
}
var primes=getPrimes(100); //an array of primes betwen 2 and 100

io.sockets.on('connection', function(socket){
	socket.on('request', function(data){
		console.log('request #id: ' + socket.id);
		b = randomInt(5,20);
		p = primes[randomInt(0,primes.length-1)];//get random prime
		g = [2,5][randomInt(0,1)];//choice between 2 and 5
		sessions.push({
			id: socket.id,
			b: b,
			p: p,
			g: g,
			B: Math.pow(g,b)%p,//server's public key
			A: 0,//client's public key
			S: 0,//secret key
			encryptionType: ""
		});
		this.emit('requestResponse', {"p":p, "g":g}); //sending modulus and base
	});
	socket.on('exchange', function(data){
		console.log('exchange #id: ' + socket.id);
		session = sessions.getSession(socket.id);
		session.A=data.A;//save client's key
		session.S = Math.pow(session.A,session.b)%session.p;
		xor = new Xorc(session.S);//new xor encryption with key=S
		this.emit('exchangeResponse',{"B":session.B}); //sending server's public key
	});
	socket.on('encryptionType', function(data){
		session = sessions.getSession(socket.id);
		session.encryptionType = data.encryption;//save encryption type
	});
	socket.on('message_to_server', function(data){
		session = sessions.getSession(socket.id);
		data = JSON.parse(data); //change string on JSON
		var decode = Base64.decode(data.message); //decoding base64
		var en; //decrypting
		switch(session.encryptionType){
			case "xor": en = xor.decrypt(decode);
			break;
			case "cezar": en =caesarShift(decode, -session.S); //minus - decoding
			break;
			default: en = decode;//encryptionType==none 
			break;
		}
		this.emit("message_to_client",{"message": "from_server: " + en});
	});
});
