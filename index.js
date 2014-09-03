var stream = require('stream');
var util = require('util');
var Buffer = require('buffer').Buffer;
var OffsetBuffer = require('obuf');

function Parser() {
  stream.Transform.call(this);
  this._readableState.objectMode = true;

  this.lineEnd = '';
  this.off = 0;
  this.offStr = this.offToStr(this.off);

  this.buffer = null;
  this.state = 'header';
  this.waiting = 1;
  this.packet = null;
};
util.inherits(Parser, stream.Transform);
module.exports = Parser;

Parser.prototype._transform = function transform(data, enc, cb) {
  var lines = (this.lineEnd + data).split(/\n/g);
  this.lineEnd = lines.pop();

  for (var i = 0; i < lines.length; i++)
    this.parseLine(lines[i].trim());

  cb();
};

Parser.prototype.offToStr = function offToStr(off) {
  var res = off.toString(16);
  if (res.length === 4)
    return '0x' + res + ':';
  else if (res.length === 3)
    return '0x0' + res + ':';
  else if (res.length === 2)
    return '0x00' + res + ':';
  else if (res.length === 1)
    return '0x000' + res + ':';
};

Parser.prototype.parseLine = function parseLine(line) {
  if (line.indexOf(this.offStr) !== 0) {
    // Reset offset
    if (this.off !== 0) {
      this.off = 0;
      this.offStr = this.offToStr(this.off);
    }
    return;
  }

  var hex = line.slice(this.offStr.length).trim().split(/\s/, 8).join('');
  var data = new Buffer(hex, 'hex');

  this.parsePacket(data);
  this.offStr = this.offToStr(this.off);
};

Parser.prototype.reset = function reset() {
  this.buffer = new OffsetBuffer();
  this.packet = null;
  this.state = 'header';
  this.waiting = 1;
};

Parser.prototype.parsePacket = function parsePacket(data) {
  if (this.off === 0)
    this.reset();

  this.buffer.push(data);
  this.off += data.length;

  try {
    while (this.buffer.size >= this.waiting) {
      if (this.state === 'header')
        this.parseHeader();
      else if (this.state === 'ihl')
        this.parseIHL();
      else if (this.state === 'body')
        this.parseBody();
      else
        throw new Error('Unknown state: ' + this.state);
    }
  } catch (e) {
    this.reset();
    this.emit('error', e);
  }
};

Parser.prototype.parseHeader = function parseHeader() {
  var fb = this.buffer.readUInt8();
  var version = fb >>> 4;
  if (version !== 4)
    return this.reset();

  var ihl = fb & 0x0f;
  if (ihl < 5)
    throw new Error('IHL is too small');

  this.state = 'ihl';
  this.waiting = ihl * 4 - 1;

  this.packet = new Packet(version, ihl);
};

var protocols = {
  6: 'tcp',
  17: 'udp'
};

Parser.prototype.parseIHL = function parseIHL() {
  var sb = this.buffer.readUInt8();
  var dscp = sb >>> 4;
  var ecn = sb & 0x0f;

  this.packet.dscp = dscp;
  this.packet.ecn = ecn;
  this.packet.total = this.buffer.readUInt16BE();
  this.packet.id = this.buffer.readUInt16BE();

  var b = this.buffer.readUInt16BE();
  this.packet.flags = b >>> 13;
  this.packet.off = b & 0x1fff;
  this.packet.ttl = this.buffer.readUInt8();
  this.packet.protocol = this.buffer.readUInt8();
  this.packet.chksum = this.buffer.readUInt16BE();
  this.packet.src = this.buffer.take(4);
  this.packet.dst = this.buffer.take(4);

  if (protocols[this.packet.protocol])
    this.packet.protocol = protocols[this.packet.protocol];

  this.state = 'body';
  this.waiting = this.packet.total - 20;
};

Parser.prototype.parseBody = function parseBody() {
  this.packet.data = this.buffer.take(this.waiting);
  if (this.packet.protocol === 'tcp')
    this.packet = this.parseTCP(this.packet);
  this.push(this.packet);

  this.reset();
};

function Packet(version, ihl) {
  this.version = version;
  this.ihl = ihl;

  this.dscp = null;
  this.ecn = null;
  this.total = null;
  this.id = null;
  this.flags = null;
  this.off = null;
  this.ttl = null;
  this.protocol = null;
  this.chksum = null;
  this.src = null;
  this.dst = null;

  this.data = null;
}

Parser.prototype.parseTCP = function parseTCP(packet) {
  var res = new TCP(packet);
  var buf = new OffsetBuffer();
  buf.push(packet.data);

  res.srcPort = buf.readUInt16BE();
  res.dstPort = buf.readUInt16BE();
  res.seq = buf.readUInt32BE();
  res.ackSeq = buf.readUInt32BE();

  var b = buf.readUInt8();
  res.dataOff = b >>> 4;
  res.ns = !!(b & 1);

  var b = buf.readUInt8();
  res.cwr = !!(b & 0x80);
  res.ece = !!(b & 0x40);
  res.urg = !!(b & 0x20);
  res.ack = !!(b & 0x10);
  res.psh = !!(b & 0x08);
  res.rst = !!(b & 0x04);
  res.syn = !!(b & 0x02);
  res.fin = !!(b & 0x01);

  res.wnd = buf.readUInt16BE();
  res.chksum = buf.readUInt16BE();
  res.urgptr = buf.readUInt16BE();

  if (res.dataOff * 4 > packet.length - buf.size)
    throw new Error('TCP packet OOB');

  res.data = packet.data.slice(res.dataOff * 4);

  return res;
};

function TCP(packet) {
  this.type = 'tcp';

  this.raw = packet;
  this.srcPort = null;
  this.dstPort = null;
  this.seq = null;
  this.ackSeq = null;
  this.dataOff = null;

  this.ns = null;
  this.cwr = null;
  this.ece = null;
  this.urg = null;
  this.ack = null;
  this.psh = null;
  this.rst = null;
  this.syn = null;
  this.fin = null;

  this.wnd = null;
  this.chksum = null;
  this.urgptr = null;

  this.data = null;
}

function Unknown(packet) {
  this.type = 'unknown';
  this.raw = packet;
}
