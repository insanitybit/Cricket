"use strict";

var os				= require('os'),
    fs        = require('fs-extra'),
		child 		= require('child_process'),
    ini       = require('ini'),
    Zip       = require('adm-zip')

var afl = function() {
  this.config     = ini.parse(fs.readFileSync('../config/config.ini', 'utf-8'));
  this.aflprocs   = [];
  this.afldir;
  this.aflpath;
  this.targetpath;
  this.testcases;
  this.instance_count = os.cpus().length;
  this.hostname;
  this.construct();
  this.running = false;
  this.fullargs;
  this.displays    = [];
};

// should no longer be necessary
afl.prototype.syncdir = function(hostname) {
  // this.hostname = hostname;
	// for (var i = 0; i < this.core_count; i++) {
	// 	var path = this.syncdir + hostname + "_fuzzer" + i;
	// 		if(!(fs.existsSync(path)))
	//       fs.mkdirSync(path);
	// }
};

// construct grabs the config values and stores them in the object's variables
// config/config.ini
afl.prototype.construct = function() {
  this.afldir     = this.config.paths.afldir;
  this.aflbin     = this.config.paths.aflbin;
  this.target     = this.config.paths.target;
  this.testcases  = this.config.paths.testcases;
  this.sync_dir   = this.config.paths.syncdir;
};



// 'start' will take the arguments for afl, and the arguments for the target
// these args are passed to genargs, which will generate 'fullargs' to be used
// for each process

// ./afl-fuzz -i testcase_dir -o sync_dir -S fuzzer03 [...other stuff...]
afl.prototype.start = function(aflargs,targetargs, resume){
  if(this.running == false){
    console.log("starting afl");
    this.fullargs = this.genargs(aflargs, targetargs, resume);
    // console.log(this.fullargs[0]);
    for(var i = 1; i < this.instance_count; i++){
      this.aflprocs[i] = child.spawn(this.aflbin, this.fullargs[i]);
    }

    this.aflprocs[0] = child.spawn(this.aflbin, this.fullargs[0]);//,
    // {  stdio: [
    //   0, // use parents stdin for child
    //   'pipe', // pipe child's stdout to parent
    //   'pipe' // direct child's stderr to a file
    // ]});
    this.running = true;
  } else {
    console.log("AFL is already running on this system");
  }

  this.regstdout();
}

// ./afl-fuzz -i testcase_dir -o sync_dir -S fuzzer03 [...other stuff...]
// TODO: Move args to config.ini and allow cricket to determine -M/-S
afl.prototype.genargs = function(aflargs, targetargs, resume){

  var fargs        = [];

  for(var i = 0; i < this.instance_count; i++){
    fargs[i]  = [];
    if(i == 0){
      fargs[i].push('-M');
      fargs[i].push('fuzzer' + i);

    } else {
      fargs[i].push('-S');
      fargs[i].push('fuzzer' + i);
    }

    fargs[i].push('-i');

    if(resume === true){
      fargs[i].push('-');
    } else {
      fargs[i].push(this.testcases);
    }

    fargs[i].push('-o');
    fargs[i].push(this.sync_dir);

    fargs[i].push(this.target);

  }

  for (var i = 0; i < this.instance_count; i++) {
    for(var j = 0; j < aflargs.length; j++){
      fargs[i].push(aflargs[j]);
      if(aflargs[j] === '-f'){
        fargs[i].push(this.afldir + 'tmp/tmfile' + i);
      }
    }
  }

  for (var i = 0; i < this.instance_count; i++) {
    for(var j = 0; j < targetargs.length; j++){
      fargs[i].push(targetargs[j]);
    }
  }
  return fargs;

}

//TODO: confirm child process closes, handle it if it doesn't
/*
.on('close', function (code, signal) {
});
*/
afl.prototype.stop = function(){
  for(var i = 1; i < this.aflprocs.length; i++){
    this.aflprocs[i].kill('SIGINT');
  }
}


// TODO: implement pause/resume using -I- to restore a session
afl.prototype.pause = function(){
  for(var i = 0; i < this.aflprocs.length; i++){
    this.aflprocs[i].kill('SIGINT');
  }
}


// Currently broken, regstdout and display are used to control which fuzzer
// is displaying at any given time. Right now the issue is that i cant seem to
// update self.displays, due to scoping issues, so it never updates
// Though I have confirmed that this method *would* work otherwise.
afl.prototype.regstdout = function(){
  for (var i = 0; i < this.aflprocs.length; i++) {
    this.displays[i] = false;
  }


  for (var i = 0; i < this.aflprocs.length; i++) {
    var self = this;
    this.aflprocs[i].stdout.on('data', function (data) {
      console.log(self.displays[i]);
        if(self.displays[i] === true)
        {    process.stdout.write(data.toString());    }
    });

    this.aflprocs[i].stderr.on('data', function (data) {
      console.log("more errors");
        // if(this.displays[i] === true)
        // {    process.stdout.write(data.toString());    }
    });
  }
}

afl.prototype.display = function(index){
  for (var i = 0; i < this.aflprocs.length; i++) {
    this.displays[i] = false;
  }

  this.displays[index] = true;
}

afl.prototype.resume = function(){

}

afl.prototype.whatsup = function(){
  this.aflprocs[0] = child.spawn(this.afldir + 'afl-whatsup',
                                 [this.sync_dir],
                                { stdio: 'inherit' });
}

/*
  get_queue will load up the queue from each fuzzer instance on the system,
  storing them in a zip, and returning it (likely to be passed to a next_worker)
*/
afl.prototype.get_queue = function(){
  var zip = new Zip();

  for(var i = 0; i < this.instance_count; i++){
    zip.addLocalFolder(this.sync_dir + 'fuzzer' + i + '/queue/');
  }

  var zipEntries = zip.getEntries();

  zipEntries.forEach(function(zipEntry) {
    if((zipEntry.entryName == '.cur_input')
    || (zipEntry.entryName == '.state/')
    || (zipEntry.entryName == '.synced/')) {
         zip.deleteFile(zipEntry);
    }
  });

  return zip;

}


// For every instance of AFL, writ ethe entirity of the queue to each instance
// TODO: Run the afl trim command to remove useless files
afl.prototype.write_queue = function(queue){
  var zip = new Zip();
  var sdir;
  for(var i = 0; i < this.instance_count; i++){
    sdir = this.sync_dir + 'fuzzer' + i + '/queue/';
    zip.extractAllTo(sdir, /*overwrite*/false);
  }
}

exports.afl 	        = afl;

exports.construct     = afl.prototype.construct;
exports.syncdir       = afl.prototype.syncdir;

exports.genargs       = afl.prototype.genargs;

exports.start         = afl.prototype.start;
exports.stop          = afl.prototype.stop;
exports.pause         = afl.prototype.pause;

exports.display       = afl.prototype.display;
exports.whatsup       = afl.prototype.whatsup;
exports.regstdout     = afl.prototype.regstdout;

exports.get_queue 	  = afl.prototype.get_queue;
exports.write_queue   = afl.prototype.write_queue;
