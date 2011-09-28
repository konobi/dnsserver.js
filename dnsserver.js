// Copyright (c) 2010 Tom Hughes-Croucher
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

var sys = require('sys'),
    Buffer = require('buffer').Buffer,
    dgram = require('dgram'),
    ctype = require('./node-ctype');

host = 'localhost';
port = 9999;

var server = dgram.createSocket('udp4');
    
server.on('message', function (msg, rinfo) {
    //split up the message into the dns request header info and the query
    var q = processRequest(msg);

    buf = createResponse(q);
    server.send(buf, 0, buf.length, rinfo.port, rinfo.address, function (err, sent) {
        
    });
});

// slices a single byte into bits
// assuming only single bytes
var sliceBits = function(b, off, len) {
    var s = 7 - (off + len - 1);

    b = b >>> s;
    return b & ~(0xff << len);
};

//takes a buffer as a request
var processRequest = function(req) {
    //see rfc1035 for more details
    //http://tools.ietf.org/html/rfc1035#section-4.1.1

    var query = {};
    query.header = {};
    //TODO write code to break questions up into an array
    query.question = {};

    var dns_parser = new ctype.Parser({ endian: 'big' }); 
    
    query.header = dns_parser.readData([
        { id: { type: 'int16_t' } },
        { header_fields1: { type: 'char' } },
        { header_fields2: { type: 'char' } },
        { qdcount: { type: 'uint16_t' } },
        { ancount: { type: 'uint16_t' } },
        { nscount: { type: 'uint16_t' } },
        { arcount: { type: 'uint16_t' } },
    ], req, 0);

    var tmpByte = query.header.header_fields1.toString('binary', 0, 1).charCodeAt(0);
    query.header.qr = sliceBits(tmpByte, 0, 1);
    query.header.opcode = sliceBits(tmpByte, 1, 4);
    query.header.aa = sliceBits(tmpByte, 5, 1);
    query.header.tc = sliceBits(tmpByte, 6, 1);
    query.header.rd = sliceBits(tmpByte, 7, 1);
    
    tmpByte = query.header.header_fields2.toString('binary', 0, 1).charCodeAt(0);
    query.header.ra = sliceBits(tmpByte, 0, 1);
    query.header.z = sliceBits(tmpByte, 1, 3);
    query.header.rcode = sliceBits(tmpByte, 4, 4);

    query.question = dns_parser.readData([
        { qname: { type: 'char[' + (req.length - 16) + ']' } },
        { qtype: { type: 'char[2]' } },
        { qclass: { type: 'char[2]' } },
    ], req, 12);

    return query;
};

var createResponse = function(query) {

    /*
    * Step 1: find record associated with query
    */
    var results = findRecords(query.question.qname, 1);

    /*
    * Step 2: construct response object
    */
    
    var response = {};
    response.header = {};

    //1 byte
    response.header.id = query.header.id; //same as query id

    //combined 1 byte
    response.header.qr = 1; //this is a response
    response.header.opcode = 0; //standard for now TODO: add other types 4-bit!
    response.header.aa = 0; //authority... TODO this should be modal
    response.header.tc = 0; //truncation
    response.header.rd = 1; //recursion asked for

    //combined 1 byte
    response.header.ra = 0; //no rescursion here TODO
    response.header.z = 0; // spec says this MUST always be 0. 3bit
    response.header.rcode = 0; //TODO add error codes 4 bit.

    //1 byte
    response.header.qdcount = 1; //1 question
    //1 byte
    response.header.ancount = results.length; //number of rrs returned from query
    //1 byte
    response.header.nscount = 0;
    //1 byte
    response.header.arcount = 0; 
    
    response.question = {};
    response.question.qname = query.question.qname;
    response.question.qtype = query.question.qtype;
    response.question.qclass = query.question.qclass;

    response.rr = results;

    /*
    * Step 3 render response into output buffer
    */
    var buf = buildResponseBuffer(response);
    
    /*
    * Step 4 return buffer
    */
    return buf;
};

var domainToQname = function(domain) {
    var tokens = domain.split(".");
    len = domain.length + 2;
    var qname = new Buffer(len);
    var offset = 0;
    for(var i=0; i<tokens.length;i++) {
        qname[offset]=tokens[i].length;
        offset++;
        for(var j=0;j<tokens[i].length;j++) {
            qname[offset] = tokens[i].charCodeAt(j);
            offset++;
        }
    }
    qname[offset] = 0;
    
    return qname;
};

var getZeroBuf = function(len) {
    buf = new Buffer(len);
    for(var i=0;i<buf.length;i++) { buf[i]=0;}
    return buf;
};

var buildResponseBuffer = function(response) {
    //calculate len in octets
    //NB not calculating rr this is done later
    //headers(12) + qname(qname + 2 + 2)
    //e.g. 16 + 2 * qname;
    //qnames are Buffers so length is already in octs
    var qnameLen = response.question.qname.length;
    var len = 16 + qnameLen;
    var buf = getZeroBuf(len);

    var dns_writer = new ctype.Parser({ endian: 'big' });

    var header_fields_1_buf = new Buffer(1);
    var header_fields_2_buf = new Buffer(1);
    header_fields_1_buf[0] = (0x00 | response.header.qr << 7 | response.header.opcode << 3 | response.header.aa << 2 | response.header.tc << 1 | response.header.rd);
    header_fields_2_buf[0] = (0x00 | response.header.ra << 7 | response.header.z << 4 | response.header.rcode);

    var layout = [
        { id: { type: 'int16_t', value: response.header.id } },
        { header_fields1: { type: 'char[1]', value: header_fields_1_buf } },
        { header_fields2: { type: 'char[1]', value: header_fields_2_buf } },
        { qdcount: { type: 'uint16_t', value: response.header.qdcount } },
        { ancount: { type: 'uint16_t', value: response.header.ancount } },
        { nscount: { type: 'uint16_t', value: response.header.nscount } },
        { arcount: { type: 'uint16_t', value: response.header.arcount } }
    ];
    dns_writer.writeData(layout, buf, 0);

    console.log(buf); 

    dns_writer.writeData([
        { qname: { type: 'char[' + response.question.qname.length + ']', value: response.question.qname } },
        { qtype: { type: 'char[2]', value: response.question.qtype } },
        { qclass: { type: 'char[2]', value: response.question.qclass } },
    ], buf, 12);

    console.log(buf); 

    var rrStart = 12+qnameLen+4;
    for (var i=0;i<response.rr.length;i++) {
        //TODO figure out if this is actually cheaper than just iterating 
        //over the rr section up front and counting before creating buf
        //
        //create a new buffer to hold the request plus the rr
        //len of each response is 14 bytes of stuff + qname len 
        var rr = response.rr[i];
        var tmpBuf = getZeroBuf(buf.length + rr.qname.length + 14);

        buf.copy(tmpBuf, 0, 0, buf.length);

        dns_writer.writeData([
            { qname: { type: 'char['+rr.qname.length+']', value: rr.qname } },
            { qtype: { type: 'char[2]', value: rr.qtype } },
            { qclass: { type: 'char[2]', value: rr.qclass } },
            { ttl:  { type: 'uint32_t', value: rr.ttl } },
            { rdlength: { type: 'uint16_t', value: rr.rdlength } },
            { rdata: { type: 'char[rdlength]', value: rr.rdata } }
        ], tmpBuf, rrStart);

        rrStart = rrStart + response.rr[i].qname.length + 14;
        
        buf = tmpBuf;
    }
 
    //TODO compression
    console.log(buf); 
   
    return buf;
};

//take a number and make sure it's written to the buffer as 
//the correct length of bytes with leading 0 padding where necessary
// takes buffer, offset, number, length in bytes to insert
var numToBuffer = function(buf, offset, num, len, debug) {
    if (typeof num != 'number') {
        throw new Error('Num must be a number');
    }

    for (var i=offset;i<offset+len;i++) {
            
            var shift = 8*((len - 1) - (i - offset));
            
            var insert = (num >> shift) & 255;
            
            buf[i] = insert;
    }
    
    return buf;
};

var findRecords = function(qname, qtype, qclass) {
    
    //assuming we are always going to get internet 
    //request but adding basic qclass support
    //for completeness 
    //TODO replace throws with error responses
    if (qclass === undefined || qclass === 1) {
        qclass = 'in';
    } else {
        throw new Error('Only internet class records supported');
    }

    var types = {
         1:   'a', //a host address
         2:   'ns', //an authoritative name server
         3:   'md', //a mail destination (Obsolete - use MX)
         4:   'mf', //a mail forwarder (Obsolete - use MX)
         5:   'cname', //the canonical name for an alias
         6:   'soa', //marks the start of a zone of authority
         7:   'mb', //a mailbox domain name (EXPERIMENTAL)
         8:   'mg', //a mail group member (EXPERIMENTAL)
         9:   'mr', //a mail rename domain name (EXPERIMENTAL)
         10:  'null', //a null RR (EXPERIMENTAL)
         11:  'wks', //a well known service description
         12:  'ptr', //a domain name pointer
         13:  'hinfo', //host information
         14:  'minfo', //mailbox or mail list information
         15:  'mx', //mail exchange
         16:  'txt', //text strings
         255: '*' //select all types
     };

    qtype = types[qtype];
    if(qtype === undefined){
        throw new Error('No valid type specified');
    }

    var domain = qnameToDomain(qname);        
    
    //TODO add support for wildcard
    if (qtype === '*') {
        throw new Error('Wildcard not supported');
    } else {
        var rr = records[domain][qclass][qtype];
    }

    
    
    return rr;
};

var qnameToDomain = function(qname) {

    var domain= '';
    for(var i=0;i<qname.length;i++) {
        if (qname[i] == 0) {
            //last char chop trailing .
            domain = domain.substring(0, domain.length - 1);
            break;
        }
        
        var tmpBuf = qname.slice(i+1, i+qname[i]+1);
        domain += tmpBuf.toString('binary', 0, tmpBuf.length);
        domain += '.';
        
        i = i + qname[i];
    }
    
    return domain;
};

server.addListener('error', function (e) {
  throw e;
});

function hextobin(hexstr) {
   buf = new Buffer(hexstr.length / 2);
   for(var i = 0; i < hexstr.length/2 ; i++) {
      buf[i] = (parseInt(hexstr[i * 2], 16) << 4) + (parseInt(hexstr[i * 2 + 1], 16));
   }
   return buf;
 }

//
//TODO create records database

records = {};
records['tomhughescroucher.com'] = {};
records['tomhughescroucher.com']['in'] = {};
records['tomhughescroucher.com']['in']['a'] = [];

var r = {};
r.qname = domainToQname('tomhughescroucher.com');
r.qtype = hextobin('0001');
r.qclass = hextobin('0001');
r.ttl = 360;
r.rdlength = 4;
r.rdata = hextobin('BC8A0009');

records['tomhughescroucher.com']['in']['a'].push(r);

r = {};
r.qname = domainToQname('tomhughescroucher.com');
r.qtype = hextobin('0001');
r.qclass = hextobin('0001');
r.ttl = 360;
r.rdlength = 4;
r.rdata = hextobin('7F000001');

records['tomhughescroucher.com']['in']['a'].push(r);

server.bind(port, host);
console.log('Started server on ' + host + ':' + port);
