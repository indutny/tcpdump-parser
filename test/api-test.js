var assert = require('assert');
var fs = require('fs');
var tp = require('../');

describe('tcpdump-parser', function() {
  it('should parse tcpdump stream', function(cb) {
    var parser = new tp();
    fs.createReadStream(__dirname + '/fixtures/dump.txt')
      .pipe(parser);

    parser.on('data', function onPacket(packet) {
      assert.equal(packet.type, 'tcp');
    });
    parser.on('end', cb);
  });
});
