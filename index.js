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

  this.status = '';
  this.buffer = null;
  this.state = 'initial';
  this.waiting = 0;
  this.packet = null;

  // 802.11
  this.rt = null;
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
  // Reset is needed
  if (line.indexOf(this.offStr) !== 0) {
    this.parseBuffer();

    // Reset offset
    if (this.off !== 0) {
      this.off = 0;
      this.offStr = this.offToStr(this.off);
    }

    if (!/^0x\d/.test(line))
      this.status = line;

    return;
  }

  var hex = line.slice(this.offStr.length).trim().split(/\s/, 8).join('');
  var data = new Buffer(hex, 'hex');

  if (this.off === 0)
    this.reset();

  this.buffer.push(data);
  this.off += data.length;
  this.offStr = this.offToStr(this.off);
};

Parser.prototype.parseBuffer = function parseBuffer() {
  if (!this.buffer)
    return;

  var wifi = /802\.11|antenna/.test(this.status);
  try {
    while (this.buffer.size >= this.waiting) {
      if (wifi)
        this.parseWifiPacket();
      else
        this.parsePacket();
    }
  } catch (e) {
    this.emit('error', e);
  }
};

Parser.prototype.reset = function reset() {
  this.buffer = new OffsetBuffer();
  this.packet = null;
  this.state = 'initial';
  this.waiting = 0;
};

Parser.prototype.parsePacket = function parsePacket(data) {
  if (this.state === 'initial') {
    this.state = 'header';
    this.waiting = 1;
  } else if (this.state === 'header') {
    this.parseHeader();
  } else if (this.state === 'ihl') {
    this.parseIHL();
  } else if (this.state === 'body') {
    this.parseBody();
  } else {
    throw new Error('Unknown state: ' + this.state);
  }
};

Parser.prototype.parseHeader = function parseHeader() {
  var fb = this.buffer.readUInt8();
  var version = fb >>> 4;
  if (version !== 4)
    throw new Error('Unknown version');

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
  else
    this.packet = new Unknown(this.packet);
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

Parser.prototype.parseWifiPacket = function parseWifiPacket() {
  if (this.state === 'initial') {
    this.state = 'rt-header';
    this.waiting = 8;
  } else if (this.state === 'rt-header') {
    this.parseRTHeader();
  } else if (this.state === 'rt-body') {
    this.parseRTBody();
  } else if (this.state === 'header') {
    this.parseWifiHeader();
  } else if (this.state === 'header-data') {
    this.parseWifiHeaderData();
  } else if (this.state === 'beacon') {
    this.parseWifiBeacon();
  } else if (this.state === 'elements') {
    this.parseWifiElements();
  } else {
    throw new Error('Unknown state: ' + this.state);
  }
};

Parser.prototype.parseRTHeader = function parseRTHeader() {
  var version = this.buffer.readUInt8();
  if (version !== 0)
    throw new Error('Invalid radiotap version');

  var pad = this.buffer.readUInt8();
  var len = this.buffer.readUInt16LE();
  var present = this.buffer.readUInt32LE();

  if (len < 8)
    throw new Error('Invalid radiotap header length');

  this.rt = {
    version: version,
    pad: pad,
    len: len,
    present: present,
    tsft: null,
    flags: null
  };
  this.state = 'rt-body';
  this.waiting = len - 8;
};

Parser.prototype.parseRTBody = function parseRTBody() {
  var bitmask = [ this.rt.present ];
  var off = 0;

  // Extended bitmask
  while ((bitmask[bitmask.length - 1] & 0x80000000) != 0) {
    if (this.buffer.size < 4)
      throw new Error('Extended bitmask OOB');

    bitmask.push(this.buffer.readUInt32LE());
    off += 4;
  }

  // Read flags
  var bflags = 0;

  // TSFT
  if (bitmask[0] & 0x01) {
    this.rt.tsft = this.buffer.take(8);
    off += 8;
  }

  if (bitmask[0] & 0x02) {
    if (this.buffer.size < 1)
      throw new Error('RT flags OOB');

    bflags = this.buffer.readUInt8();
    off++;
  }

  this.rt.flags = {
    cfp: !!(bflags & 0x01),
    short: !!(bflags & 0x02),
    wep: !!(bflags & 0x04),
    frag: !!(bflags & 0x08),
    fcs: !!(bflags & 0x10),
    pad: !!(bflags & 0x20),
    fcsFailure: !!(bflags & 0x40)
  };

  // Skip the rest
  this.buffer.skip(this.waiting - off);

  this.state = 'header';
  this.waiting = 2;
};

var wifiTypes = {
  0: 'management',
  1: 'control',
  2: 'data'
};

var wifiMgmtSubtypes = {
  0x00: 'assocReq',
  0x01: 'assocRes',
  0x02: 'reassocReq',
  0x03: 'reassonRes',
  0x04: 'probeReq',
  0x05: 'probeRes',
  0x08: 'beacon',
  0x09: 'atim',
  0x0a: 'disassoc',
  0x0b: 'auth',
  0x0c: 'deauth',
  0x0d: 'act'
};

var wifiCtrlSubtypes = {
  0x08: 'bar',
  0x09: 'ba',
  0x0a: 'psPoll',
  0x0b: 'rts',
  0x0c: 'cts',
  0x0d: 'ack',
  0x0e: 'cfEnd',
  0x0f: 'cfEndAck'
};

Parser.prototype.parseWifiHeader = function parseWifiHeader() {
  var fw = this.buffer.readUInt16LE();
  var version = fw & 0x3;
  if (version !== 0)
    throw new Error('Invalid 802.11 version');

  var type = (fw >> 2) & 0x3;
  var subtype = (fw >> 4) & 0xf;
  var flags = fw >> 8;
  flags = {
    toDS: !!(flags & 0x01),
    fromDS: !!(flags & 0x02),
    moreFrag: !!(flags & 0x04),
    retry: !!(flags & 0x08),
    pwr: !!(flags & 0x10),
    moreData: !!(flags & 0x20),
    wep: !!(flags & 0x40)
  };

  var type = wifiTypes[type];

  // Just a size helpers
  var sz = {
    fc: 2,
    dur: 2,
    da: 6,
    sa: 6,
    bssid: 6,
    seq: 2,
    ra: 6,
    ta: 6,
    ctl: 2,
    aid: 2
  };

  // Management
  var len = 0;
  if (type === 'management') {
    subtype = wifiMgmtSubtypes[subtype];
    len = sz.fc + sz.dur + sz.da + sz.sa + sz.bssid + sz.seq;

  // Control
  } else if (type === 'control') {
    subtype = wifiCtrlSubtypes[subtype];

    if (subtype === 'bar')
      len = sz.fc + sz.dur + sz.ra + sz.ta + sz.ctl + sz.seq;
    else if (subtype === 'poll')
      len = sz.fc + sz.aid + sz.bssid + sz.ta;
    else if (subtype === 'rts')
      len = sz.fc + sz.dur + sz.ra + sz.ta;
    else if (subtype === 'cts' || subtype === 'ack')
      len = sz.fc + sz.dur + sz.ra;
    else if (subtype === 'cfEnd' || subtype === 'cfEndAck')
      len = sz.fc + sz.dur + sz.ra + sz.bssid;

  // Data
  } else if (type === 'data') {
    len = (flags.toDS && flags.fromDS) ? 30 : 24;

    // TODO(indutny): support QoS?
  }

  if ((type !== 'data' && !subtype) || len === 0)
    throw new Error('Unknown frame type+subtype: ' + type + ' : ' + subtype);

  var pad = 0;
  if (this.rt.flags.fcs)
    this.buffer = this.buffer.clone(this.buffer.size - 4);
  if (this.rt.flags.pad && (len & 0x3) !== 0)
    pad += 4 - (len & 0x3);

  this.packet = {
    rt: this.rt,

    version: version,
    type: type,
    subtype: subtype,
    flags: flags,
    body: null,

    length: len,
    padding: pad
  };

  // Exclude already parsed FC
  this.waiting = this.packet.length + this.packet.padding - 2;
  this.state = 'header-data';
};

Parser.prototype.parseWifiHeaderData = function parseWifiHeaderData() {
  var body = this.buffer.clone(this.packet.length);

  // Skip length + padding
  this.buffer.skip(this.waiting);

  var type = this.packet.type;
  var subtype = this.packet.subtype;
  var data = null;
  if (type === 'management') {
    data = {
      dur: body.readUInt16LE(),
      dest: body.take(6),
      src: body.take(6),
      bssid: body.take(6),
      seq: body.readUInt16LE()
    };
  } else if (type === 'control') {
    if (subtype === 'bar') {
      data = {
        dur: body.readUInt16LE(),
        ra: body.take(6),
        ta: body.take(6),
        ctl: body.readUInt16LE(),
        seq: body.readUInt16LE()
      };
    } else if (subtype === 'poll') {
      data = {
        aid: body.readUInt16LE(),
        bssid: body.take(6),
        ta: body.take(6)
      };
    } else if (subtype === 'rts') {
      data = {
        dur: body.readUInt16LE(),
        ra: body.take(6),
        ta: body.take(6)
      };
    } else if (subtype === 'cts' || subtype === 'ack') {
      data = {
        dur: body.readUInt16LE(),
        ra: body.take(6)
      };
    } else if (subtype === 'cfEnd' || subtype === 'cfEndAck') {
      data = {
        dur: body.readUInt16LE(),
        ra: body.take(6),
        bssid: body.take(6)
      };
    }
  }

  this.packet.headerData = data;

  if (type === 'management') {
    if (subtype === 'beacon') {
      this.waiting = 12;
      this.state = 'beacon';
    }
  }

  if (this.state === 'header-data') {
    // Report raw data
    this.packet.body = this.buffer.take(this.buffer.size);
    this.packet = new Unknown(this.packet);
    this.push(this.packet);
    this.reset();
  }
};

Parser.prototype.parseWifiBeacon = function parseWifiBeacon() {
  this.packet = new WifiBeacon(this.packet, {
    timestamp: this.buffer.take(8),
    interval: this.buffer.readUInt16LE(),
    cap: this.buffer.readUInt16LE()
  });

  this.waiting = 2;
  this.state = 'elements';
};

var wifiElements = {
  0: 'ssid',
  1: 'dataRates',
  2: 'freqSet',
  3: 'dirSet',
  4: 'contFree',
  5: 'trafMap',
  6: 'ibss',
  7: 'country',
  0x24: 'channels',
  0x2d: 'hpCap',
  0x2e: 'qosCap',
  0x30: 'rsn',
  0x34: 'apReport',
  0x3d: 'hpInfo'
};

Parser.prototype.parseWifiElements = function parseWifiElements() {
  var elements = {};
  while (this.buffer.size > 0) {
    if (this.buffer.size < 2)
      throw new Error('Invalid element header');

    var id = this.buffer.readUInt8();
    var len = this.buffer.readUInt8();
    if (this.buffer.size < len)
      throw new Error('Element length OOB');

    id = wifiElements[id] || id;
    elements[id] = this.buffer.take(len);
    if (id === 'ssid')
      elements[id] = elements[id].toString();
  }

  this.packet.elements = elements;
  this.push(this.packet);
  this.reset();
};

function WifiBeacon(packet, info) {
  this.type = 'wifi';
  this.subtype = 'beacon';

  this.raw = packet;

  this.timestamp = info.timestamp;
  this.interval = info.interval;
  this.cap = info.cap;

  this.elements = null;
}

function Unknown(packet) {
  this.type = 'unknown';
  this.raw = packet;
}
