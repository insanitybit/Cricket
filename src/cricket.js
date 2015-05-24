/*
	-M master node
	-W worker node
	--mp=[hostname + port]  Allows registering with a master node
	--qi=[time]	Sets the interval (in minutes) for sending queues
*/

var app						= require('http').createServer(),
		ioClient  		= require('socket.io-client'),
		io 						= require('socket.io')(app),
		createWorker	= require('./worker.js').createWorker,
    fs          	= require('fs'),
		afl  					= require('./afl'),
		ini       		= require('ini')

var argv = require('minimist')(process.argv.slice(2))

var port = 8080
var myhostname = require('os').hostname()
var config = '../config/'

var isMaster = false
var next_nodes 	= []
var all_nodes 	= {}

handleargs(argv)
app.listen(port)
afl.afl()

/*
	These are the commands that workers will receive
*/

io.on('connection', function (socket) {
  'use strict'
  console.log('new connection')

  socket.on('add_worker', function (hostname) {
    var tw = createWorker({
					'hostname': hostname,
					'socket': ioClient(hostname)
					})
    next_nodes.push(tw)
  })

  socket.on('request_register', function (masterhost) {
    var master = ioClient(masterhost)
    master.emit('register', myhostname + ':' + port)
  })

  socket.on('send_queue', function () {
    console.log('Sending queue now')

    var myQueue = afl.get_queue()

    next_nodes.forEach(function (node) {
      node.emit('take_queue', myQueue)
    })

  })

	//

  socket.on('take_queue', function (queue) {
    console.log('receiving queue now')
    afl.write_queue(queue)
  })

  socket.on('start_work', function (aflargs, targetargs, resume) {
    console.log('Starting work')
    afl.start(aflargs, targetargs, resume)
  })

})

// Events meant for the master
io.on('connection', function (socket) {
	// Allows other nodes to register with the master
  if (isMaster) {
    socket.emit('request_register', myhostname)

    socket.on('register', function (hostname) {
      console.log('registering new node: ' + hostname)
      var tw = createWorker({
				'hostname': hostname,
				'socket': ioClient(hostname)
				})
      all_nodes[hostname] = tw
    })

  }

})

function handleargs (argv) {

  if ((argv.M === false) && (argv.W === undefined)) {
    console.log('ERROR: Must provide -M or -W')
    process.exit(1)
  }

  if (argv.M) {
    isMaster = true
  }

  if (argv.W) {
    if (argv.mp !== undefined) {
      console.log('Registering with master')
      var master = ioClient(argv.mp)
      master.emit('register', myhostname + ':' + port)
    }
  }
}

var readline = require('readline')

var rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
})

// convert this to object/ map syntax eventually

rl.on('line', function (cmd) {
  switch (cmd) {
  case 'help':
			console.log('load\nlink\nwork\n'
			+ 'stop\npassq\ndisplayall')
			break

  case 'load':
      loadlist()
      break

  case 'link':
      linknodes()
      break

  case 'work':
			startwork()
      break

  case 'stop':
      stopwork()
      break

  case 'passq':
      passq()
      break

  case 'display':
      display()
      break

  case 'pause':
			pause()
			break

  case 'resume':
			resume()
			break

  case 'whatsup':
			afl.whatsup()
			break

  default:
			console.log('load\nlink\nwork' +
			'\nstop\npause\npassq\ndisplayall' +
			'\nwhatsup')
      break
  }
})

/*
	Loads a file of hostnames in ./config/hosts
	Creates a client socket for each of these
*/
function loadlist () {
  var config = ini.parse(fs.readFileSync('../config/config.ini', 'utf-8'))
  var hosts = config.hostnames.hosts

  if (hosts.length === 0) {
    console.log('no hosts found in file, nothing to do')
    return
  }

  console.log('hosts read, pushing to all nodes')

  hosts.forEach(function (host) {
    console.log('loading ' + host)
    var tw = createWorker({
					'hostname': host,
					'socket': ioClient(host)
				})
    all_nodes[host] = tw
  })
}

/*

	linknodes reads the pairs file ../config/pairs.json
	If the .one host is MASTER, we (the master) directly link to .two
	If the .two host is MASTER, we replace the the .two with the master hostname
	Otherwise, send the .one the .two host to connect to
*/

function linknodes () {
  var pairs = JSON.parse(fs.readFileSync(config + 'pairs.json').toString()).nodes

  for (var i = 0; i < pairs.length; i++) {

    if (pairs[i].one === 'MASTER') {
      var tw = createWorker({
				'hostname': pairs[i].two,
				'socket': ioClient(pairs[i].two)
				})
      next_nodes.push(tw)
		} else if (pairs[i].two === 'MASTER') {
  pairs[i].two = myhostname
  all_nodes[pairs[i].one].socket.emit('add_worker', pairs[i].two)
  all_nodes[pairs[i].one].pushHost(pairs[i].two)
		} else {
  all_nodes[pairs[i].one].socket.emit('add_worker', pairs[i].two)
  all_nodes[pairs[i].one].pushHost(pairs[i].two)
		}

  }
}

/*
	startwork emits the 'start_work' event to every worker in all_nodes
*/

function startwork () {
  var config = ini.parse(fs.readFileSync('../config/config.ini', 'utf-8'))

  var aflargs = config.afl.args.aargs
  if (aflargs === 'null') {
    aflargs = []
  }

  var targs = config.target.args.targs
  if (targs === 'null') {
    targs = []
  }

  var interval = config.interval.minutes

  interval = interval * 60 * 1000

  Object.keys(all_nodes).forEach(function (key) {
    var val = all_nodes[key]
		// Tell the other workers it's time to start
    val.socket.emit('start_work', aflargs, targs, false)
  })

  afl.start(aflargs, targs, false)
	// afl.start(aflargs, targetargs);
  setInterval(function () {
    console.log('emitting pass_queue')
    Object.keys(all_nodes).forEach(function (key) {
      all_nodes[key].socket.emit('pass_queue')
    })
  }, interval)

}

function pause () {
	// TODO: Imlpement pause with the following logic,
	// Ctrl-C, then resume by replacing -i <dir> with -i-.
	// Also, make sure to pause queue interval
  afl.pause()
}

// TODO: Detect when to resume and when to start, and build that into the
// cricket logic so that it's only one command
function resume () {
  var config = ini.parse(fs.readFileSync('../config/config.ini', 'utf-8'))

  var aflargs = config.afl.args.aargs
  if (aflargs === 'null') {
    aflargs = []
  }

  var targs = config.target.args.targs
  if (targs === 'null') {
    targs = []
  }

  var interval = config.interval.minutes

  interval = interval * 60 * 1000

  Object.keys(all_nodes).forEach(function (key) {
    all_nodes[key].socket.emit('start_work', aflargs, targs, true)
  })

  afl.start(aflargs, targs, true)
}

function stopwork () {
  afl.stop()
}

function passq () {
  Object.keys(all_nodes).forEach(function (key) {
    all_nodes[key].socket.emit('pass_queue')
  })
}

// show hostname + next_hosts of hostname
function display () {
  afl.display(0)
	// console.log('There are ' + all_nodes.size + ' nodes');
	// Object.keys(all_nodes).forEach(function (key) {
	//   var val = all_nodes[key];
	// 	for (var i = 0; i < val.next_hosts.length; i++) {
	// 		console.log('item ' + all_nodes[i]);
	// 	  console.log(val.hostname + '->' + val.next_hosts[i]);
	// 	}
	// });
}
